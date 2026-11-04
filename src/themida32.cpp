// Magicmida - C++ port
// 32-bit Themida/WinLicense unpacking logic (ported from Themida.pas).
#include "themida32.h"

#include "antidump_fix.h"
#include "patcher.h"
#include "reloc_fix.h"
#include "scyllahide.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace magicmida {
namespace {

constexpr uint32_t STATUS_SUCCESS = 0;
constexpr uint32_t STATUS_PORT_NOT_SET = 0xC0000353;

}  // namespace

ThemidaDebugger::ThemidaDebugger(const std::wstring& executable,
                                 const std::wstring& parameters,
                                 bool createData, bool useScyllaHide,
                                 bool fixRelocations)
    : ThemidaCommon(executable, parameters) {
  createDataSections_ = createData;
  useScyllaHide_ = useScyllaHide;
  fixRelocations_ = fixRelocations;
}

// --------------------------------------------------------------------------
// Debugger hooks
// --------------------------------------------------------------------------

void ThemidaDebugger::OnDebugStart(HANDLE& hPE, HANDLE hThread) {
  if (ExtractFileName(executable_).size() >= 50) {
    // "unpacking a sha256? get rekt!"
    Log(ltWarning, "Long filenames crash some Themida versions (recommend <50)");
  }

  closeHandleAPI_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CloseHandle"));
  SetBreakpoint(reinterpret_cast<uintptr_t>(closeHandleAPI_),
                HWBPType::Execute, false);

  bool scyllaInjected = false;
  if (useScyllaHide_) {
    std::string scyllaError;
    scyllaInjected = scyllahide::Start(process_.hProcess, process_.dwProcessId,
                                       scyllahide::DefaultProfile(),
                                       &scyllaError);
    if (scyllaInjected) {
      LogF(ltGood, "Applying embedded ScyllaHide (%s)",
           scyllahide::Version());
    } else {
      LogF(ltWarning,
           "ScyllaHide injection failed: %s; falling back to internal "
           "anti-anti-debug handling",
           scyllaError.c_str());
    }
  } else {
    Log(ltWarning,
        "ScyllaHide disabled by the Disable ScyllaHide option; using internal "
        "anti-anti-debug handling");
  }

  if (!scyllaInjected) {
    ntSIT_ = reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetInformationThread"));
    SetBreakpoint(reinterpret_cast<uintptr_t>(ntSIT_), HWBPType::Execute, false);
    kiFastSystemCall_ = reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "KiFastSystemCall"));

    BOOL wow64 = FALSE;
    if (!(IsWow64Process(process_.hProcess, &wow64) && wow64)) {
      SetSoftBP(reinterpret_cast<uintptr_t>(kiFastSystemCall_));
      ntQIP_ = *reinterpret_cast<const uint32_t*>(
                   reinterpret_cast<uintptr_t>(GetProcAddress(
                       GetModuleHandleW(L"ntdll.dll"),
                       "ZwQueryInformationProcess")) +
                   1);
    } else {
      wow64_ = true;
      ntQIP64_ = reinterpret_cast<void*>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "ZwQueryInformationProcess"));
      SetBreakpoint(reinterpret_cast<uintptr_t>(ntQIP64_), HWBPType::Execute,
                    false);
    }
  }

  virtualProtectAPI_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect"));

  sleepAPI_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep"));
  lstrlenAPI_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "lstrlen"));

  UpdateDR(hThread);

  TMInit(hPE);
}

DWORD ThemidaDebugger::OnAccessViolation(
    HANDLE hThread, const EXCEPTION_RECORD& exceptionRecord) {
  if (IsGuardedAddress(exceptionRecord.ExceptionInformation[1])) {
    return ProcessGuardedAccess(hThread, exceptionRecord);
  }
  return ThemidaCommon::OnAccessViolation(hThread, exceptionRecord);
}

void ThemidaDebugger::OnDLLLoad(const std::wstring& fileName,
                                void* baseAddress) {
  const std::string lowered = AsciiLowerCase(WideToUtf8(fileName));
  if (lowered.find("\\mscoree.dll") != std::string::npos) {
    Log(ltInfo, "This might be a .NET program - setting _CorExeMain BP");
    const HMODULE hCorEE = LoadLibraryW(L"mscoree.dll");  // Load in this process
    if (hCorEE == baseAddress) {
      corExeMain_ = reinterpret_cast<void*>(
          GetProcAddress(hCorEE, "_CorExeMain"));
      SetSoftBP(reinterpret_cast<uintptr_t>(corExeMain_));
    } else {
      Log(ltFatal, "DLL was loaded at different base than in target!");
    }
  }

  scyllahide::OnDllLoad(fileName);

  ThemidaCommon::OnDLLLoad(fileName, baseAddress);
}

void ThemidaDebugger::OnHardwareBreakpoint(HANDLE hThread, uintptr_t bpAddress,
                                           CONTEXT& context) {
  const uintptr_t eip = context.Eip;

  if (eip == reinterpret_cast<uintptr_t>(closeHandleAPI_)) {
    uint32_t buf = 0;
    RPM(context.Esp, &buf, 4);

    if (buf < imageBoundary_) {
      ResetBreakpoint(eip);
      if (compressed_) {
        SetBreakpoint(imageBase_ + 0x1000, HWBPType::Access);
      } else {
        SetBreakpoint(reinterpret_cast<uintptr_t>(allocMemAPI_));
      }
    }
  } else if (eip == reinterpret_cast<uintptr_t>(allocMemAPI_)) {
    // NT-Layer ZwAllocateVirtualMemory <- kernelbase.VirtualAllocEx <-
    // kernelbase.VirtualAlloc
    //                                       ^^^ not for NT 6.3
    uint32_t buf = 0;
    RPM(context.Ebp, &buf, 4);
    if ((buf - context.Ebp) < 0x40) {
      RPM(buf + 4, &buf, 4);
    } else {
      RPM(context.Ebp + 4, &buf, 4);
    }
    LogF(ltInfo, "AllocMem called from %.8X", buf);

    if ((buf >> 31) != 0) {  // Kernel address, can't be right
      Log(ltFatal, "AllocMem called from a kernel address, aborting.");
      return;
    }

    if (buf > imageBase_ && buf < imageBoundary_) {
      ++allocMemCounter_;
      if (allocMemCounter_ == (compressed_ ? 4 : 5)) {
        ResetBreakpoint(reinterpret_cast<uintptr_t>(allocMemAPI_));
        if (!themidaV3_) {
          Log(ltGood, "IAT fixing started.");
          TMIATFix(buf);
        } else {
          InstallCodeSectionGuard(PAGE_NOACCESS);
        }
      }
    }
  } else if (eip == reinterpret_cast<uintptr_t>(cmpImgBase_)) {
    ResetBreakpoint(reinterpret_cast<uintptr_t>(cmpImgBase_));
    TMIATFix3(eip);
  } else if (eip == reinterpret_cast<uintptr_t>(magicJump_)) {
    ResetBreakpoint(reinterpret_cast<uintptr_t>(magicJump_));
    TMIATFix4();
  } else if (eip == mj1_) {
    ResetBreakpoint(mj1_);
    TMIATFix5(context.Eax);
  } else if (eip == reinterpret_cast<uintptr_t>(magicJumpV1_)) {
    ResetBreakpoint(reinterpret_cast<uintptr_t>(magicJumpV1_));
    TMIATFixThemidaV1(reinterpret_cast<uintptr_t>(magicJumpV1_));
  } else if (eip == reinterpret_cast<uintptr_t>(allocHeapAPI_)) {
    Log(ltFatal, "Special IAT fix failed, perhaps not needed for this binary");
    ResetBreakpoint(reinterpret_cast<uintptr_t>(allocHeapAPI_));
    SoftBPClear();
    InstallCodeSectionGuard(PAGE_NOACCESS);
  } else if (eip == reinterpret_cast<uintptr_t>(virtualProtectAPI_)) {
    // Ensure we break on execution in case it's still on PAGE_READONLY.
    InstallCodeSectionGuard(PAGE_NOACCESS);
  } else if (eip == reinterpret_cast<uintptr_t>(ntSIT_)) {
    uint32_t buf = 0;
    uint32_t infoClass = 0;
    if (RPM(context.Esp, &buf, 4) && buf < imageBoundary_ &&
        RPM(context.Esp + 8, &infoClass, 4) && infoClass == 17) {
      Log(ltGood, "Ignoring NtSetInformationThread(ThreadHideFromDebugger)");
      context.Esp += 5 * 4;  // 4 parameters + ret
      context.Eip = buf;
      context.Eax = STATUS_SUCCESS;
      context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
      if (!SetThreadContext(hThread, &context)) {
        Log(ltFatal, "[NtSetInformationThread] SetContextThread");
      }
    }
  } else if (wow64_ && eip == reinterpret_cast<uintptr_t>(ntQIP64_)) {
    uint32_t buf = 0;
    uint32_t infoClass = 0;
    if (RPM(context.Esp, &buf, 4) && RPM(context.Esp + 8, &infoClass, 4) &&
        (infoClass == 7 || infoClass == 30)) {
      if (infoClass == 7) {
        Log(ltGood, "Faking ProcessDebugPort");
      } else {
        Log(ltGood, "Faking ProcessDebugObjectHandle");
      }
      uint32_t buf2 = 0;
      RPM(context.Esp + 12, &buf2, 4);
      const uint32_t writeBuf = 0;  // Debug Port/Debug Object Handle
      WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(buf2),
                         &writeBuf, 4, nullptr);
      context.Esp += 6 * 4;  // 5 parameters + ret
      context.Eip = buf;
      if (infoClass == 7) {
        context.Eax = STATUS_SUCCESS;
      } else {
        context.Eax = STATUS_PORT_NOT_SET;
      }
      context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
      if (!SetThreadContext(hThread, &context)) {
        Log(ltFatal, "[KiFastSystemCall] SetContextThread");
      }
    }
  } else if (bpAddress == imageBase_ + 0x1000) {
    ++baseAccessCount_;
    LogF(ltGood, "Accessed text base from %p", reinterpret_cast<void*>(eip));
    if (!baseAccessed_) {
      ResetBreakpoint(imageBase_ + 0x1000);
      SetBreakpoint(imageBase_ + 0x1000, HWBPType::Write);
      baseAccessed_ = true;
    } else {
      if (TMFinderCheck(&context)) {
        ResetBreakpoint(imageBase_ + 0x1000);
        SetBreakpoint(reinterpret_cast<uintptr_t>(allocMemAPI_),
                      HWBPType::Execute);
        repEIP_ = context.Eip;
      } else if (baseAccessCount_ == 3 && !themidaV2BySections_) {
        // Hackish, but seems ok so far.
        themidaV3_ = true;
        Log(ltInfo, "Assuming Themida v3");
        SelectThemidaSection(context.Eip);
        ResetBreakpoint(imageBase_ + 0x1000);
        SetBreakpoint(reinterpret_cast<uintptr_t>(allocMemAPI_),
                      HWBPType::Execute);
      }
    }
  } else {
    LogF(ltInfo, "Accessed %llx from %p",
         static_cast<unsigned long long>(bpAddress),
         reinterpret_cast<void*>(eip));
  }
}

DWORD ThemidaDebugger::OnSinglestep(uintptr_t bpAddress) {
  if (guardStepping_) {
    DWORD oldProtect = 0;
    VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guardStart_),
                     guardEnd_ - guardStart_, guardProtection_, &oldProtect);
    guardStepping_ = false;
    return DBG_CONTINUE;
  }

  return ThemidaCommon::OnSinglestep(bpAddress);
}

SoftBPAction ThemidaDebugger::OnSoftwareBreakpoint(HANDLE hThread,
                                                   uintptr_t bpAddress) {
  CONTEXT context{};
  context.ContextFlags = CONTEXT_FULL;
  GetThreadContext(hThread, &context);

  if (!wow64_ && bpAddress == reinterpret_cast<uintptr_t>(kiFastSystemCall_)) {
    uint32_t result = 0;
    uint32_t infoClass = 0;
    if (context.Eax == ntQIP_ && RPM(context.Esp, &result, 4) &&
        RPM(context.Esp + 12, &infoClass, 4) &&
        (infoClass == 7 || infoClass == 30)) {
      if (infoClass == 7) {
        Log(ltGood, "Faking ProcessDebugPort");
      } else {
        Log(ltGood, "Faking ProcessDebugObjectHandle");
      }
      uint32_t address = 0;
      RPM(context.Esp + 16, &address, 4);
      const uint32_t writeBuf = 0;  // Debug Port
      WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(address),
                         &writeBuf, 4, nullptr);
      context.Esp += 4;  // 5 parameters + ret
      context.Eip = result;
      if (infoClass == 7) {
        context.Eax = STATUS_SUCCESS;
      } else {
        context.Eax = STATUS_PORT_NOT_SET;
      }
    } else {
      context.Edx = context.Esp;
      context.Eip = reinterpret_cast<uintptr_t>(kiFastSystemCall_) + 2;
    }

    if (!SetThreadContext(hThread, &context)) {
      Log(ltFatal, "[KiFastSystemCall] SetContextThread");
    }
    return SoftBPAction::KeepContinueNoStep;
  }

  if (bpAddress == reinterpret_cast<uintptr_t>(corExeMain_)) {
    DumperDotnet dumper(process_, imageBase_);
    dumper.DumpToFile(ExtractFilePath(executable_) +
                      ChangeFileExt(ExtractFileName(executable_),
                                    L"U" + ExtractFileExt(executable_)));
    Log(ltGood, ".NET process dumped.");
    MarkSuccess();

    hideThreadEnd_ = true;
    TerminateProcess(process_.hProcess, 0);
    return SoftBPAction::ClearContinue;
  }

  LogF(ltInfo, "Software breakpoint at %p",
       reinterpret_cast<void*>(bpAddress));

  // Should only be called during IAT patching.
  // eax should hold a module base now.
  if (!newVer_) {
    const HMODULE mK32 = GetModuleHandleW(L"kernel32.dll");
    const HMODULE mU32 = GetModuleHandleW(L"user32.dll");
    const HMODULE mA32 = GetModuleHandleW(L"advapi32.dll");
    if (context.Eax != reinterpret_cast<uintptr_t>(mK32) &&
        context.Eax != reinterpret_cast<uintptr_t>(mU32) &&
        context.Eax != reinterpret_cast<uintptr_t>(mA32)) {
      // Rare path in certain weird binaries.
      LogF(ltInfo, "eax: %.8X", context.Eax);
      if (!IsHWBreakpoint(reinterpret_cast<uintptr_t>(allocHeapAPI_))) {
        SetBreakpoint(reinterpret_cast<uintptr_t>(allocHeapAPI_),
                      HWBPType::Execute);
      }
      // Restore original byte and single step.
      return SoftBPAction::KeepContinue;
    }

    SoftBPClear();

    const uintptr_t jumper =
        5 + context.Eip +
        *reinterpret_cast<const uint32_t*>(
            tmSect_ + (context.Eip + 1 - tmSectR_.Address));

    const uintptr_t result = reinterpret_cast<uintptr_t>(
        VirtualAllocEx(process_.hProcess, nullptr, 128, MEM_COMMIT,
                       PAGE_EXECUTE_READWRITE));
    LogF(ltInfo, "IAT patch location: %08llX",
         static_cast<unsigned long long>(result));

    uint8_t bytes[41]{};
    uint8_t* buf = bytes;
    *reinterpret_cast<uint16_t*>(buf) = 0xF881;  // cmp eax
    *reinterpret_cast<uint32_t*>(buf + 2) =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mK32));
    *reinterpret_cast<uint32_t*>(buf + 6) = 0xF8811574;
    *reinterpret_cast<uint32_t*>(buf + 10) =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mA32));
    *reinterpret_cast<uint32_t*>(buf + 14) = 0xF8810D74;
    *reinterpret_cast<uint32_t*>(buf + 18) =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mU32));
    *reinterpret_cast<uint16_t*>(buf + 22) = 0x0574;
    buf[24] = 0xE9;
    *reinterpret_cast<uint32_t*>(buf + 25) = static_cast<uint32_t>(
        jumper - (result + 24) - 5);
    *reinterpret_cast<uint64_t*>(buf + 29) = 0xE9000002872404C7ull;
    *reinterpret_cast<uint32_t*>(buf + 37) = static_cast<uint32_t>(
        jumper - (result + 36) - 5);
    WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(result), buf,
                       41, nullptr);
    FlushInstructionCache(process_.hProcess, reinterpret_cast<void*>(result),
                          41);

    buf[0] = 0xE9;
    *reinterpret_cast<uint32_t*>(buf + 1) = static_cast<uint32_t>(
        result - context.Eip - 5);
    WriteProcessMemory(process_.hProcess,
                       reinterpret_cast<void*>(context.Eip), buf, 5, nullptr);
    FlushInstructionCache(process_.hProcess,
                          reinterpret_cast<void*>(context.Eip), 5);

    Log(ltGood, "Special IAT patch was successfully written!");
  } else {
    // Teflon time!
    for (EFLRecord& efl : efls_) {
      if (efl.Address == 0) {
        efl.Address = bpAddress;
        if (InstallEFLPatch(bpAddress, context, efl)) {
          return SoftBPAction::ClearContinue;
        }
        break;
      }
    }

    SoftBPClear();
    Log(ltInfo, "Found no base in registers!");
    Log(ltGood, "Special >> NEW << IAT Patch was written!");
  }

  if (!ancientVer_) {
    // Not using PAGE_NOACCESS here is a performance optimization for some
    // targets (esp. MC1.14).
    InstallCodeSectionGuard(PAGE_READONLY);
  } else {
    InstallCodeSectionGuard(PAGE_NOACCESS);
  }
  Log(ltInfo, "Please wait, call site tracing might take a while...");
  return SoftBPAction::ClearContinue;
}

bool ThemidaDebugger::InstallEFLPatch(uintptr_t eip, CONTEXT& context,
                                      EFLRecord& record) {
  std::array<HMODULE, 3> bases = {GetModuleHandleW(L"kernel32.dll"),
                                  GetModuleHandleW(L"user32.dll"),
                                  GetModuleHandleW(L"advapi32.dll")};

  DISASM dis{};
  dis.EIP = reinterpret_cast<uintptr_t>(tmSect_) + eip - tmSectR_.Address;
  if (DisasmCheck(dis) == 5) {
    if (*(tmSect_ + (eip - tmSectR_.Address)) == 0xE9) {
      throw std::runtime_error("efl oldstyle");
    }
  }

  HMODULE foundBase = nullptr;
  uint16_t regComp = 0;
  for (HMODULE module : bases) {
    if (context.Eax == reinterpret_cast<uintptr_t>(module)) {
      regComp = 0xF881;
    } else if (context.Ecx == reinterpret_cast<uintptr_t>(module)) {
      regComp = 0xF981;
    } else if (context.Edx == reinterpret_cast<uintptr_t>(module)) {
      regComp = 0xFA81;
    } else if (context.Ebx == reinterpret_cast<uintptr_t>(module)) {
      regComp = 0xFB81;
    } else if (context.Ebp == reinterpret_cast<uintptr_t>(module)) {
      regComp = 0xFD81;
    } else if (context.Esi == reinterpret_cast<uintptr_t>(module)) {
      regComp = 0xFE81;
    } else if (context.Edi == reinterpret_cast<uintptr_t>(module)) {
      regComp = 0xFF81;
    } else {
      continue;
    }

    foundBase = module;
    break;
  }

  if (foundBase == nullptr) {
    return false;
  }

  void* hookDest = VirtualAllocEx(process_.hProcess, nullptr, 128, MEM_COMMIT,
                                  PAGE_EXECUTE_READWRITE);
  if (hookDest == nullptr) {
    return false;
  }

  uint8_t bytes[128]{};
  uint8_t* buf = bytes;
  *reinterpret_cast<uint16_t*>(buf) = regComp;
  *reinterpret_cast<uint32_t*>(buf + 2) =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bases[0]));
  *reinterpret_cast<uint16_t*>(buf + 6) = 0x2874;
  *reinterpret_cast<uint16_t*>(buf + 8) = regComp;
  *reinterpret_cast<uint32_t*>(buf + 10) =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bases[1]));
  *reinterpret_cast<uint16_t*>(buf + 14) = 0x2074;
  *reinterpret_cast<uint16_t*>(buf + 16) = regComp;
  *reinterpret_cast<uint32_t*>(buf + 18) =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bases[2]));
  *reinterpret_cast<uint16_t*>(buf + 22) = 0x1874;
  *reinterpret_cast<uint16_t*>(buf + 24) = 0x1DEB;  // jmp to OrigOps
  *reinterpret_cast<uint64_t*>(buf + 0x30) =
      0x90000002462404C7ull;  // mov [esp], 0x246 (EFL patch)
  uint8_t* originalOps = buf + 0x37;

  uint32_t totalSize = 0;
  dis.EIP = reinterpret_cast<uintptr_t>(tmSect_) + eip - tmSectR_.Address;
  while (totalSize < 5) {
    const uintptr_t length = DisasmCheck(dis);
    totalSize += static_cast<uint32_t>(length);
    dis.EIP += length;
  }

  // Copy original opcodes.
  std::memcpy(originalOps, tmSect_ + (eip - tmSectR_.Address), totalSize);
  record.Original.assign(originalOps, originalOps + totalSize);
  // Calculate jump back.
  originalOps += totalSize;
  *originalOps = 0xE9;
  *reinterpret_cast<uint32_t*>(originalOps + 1) = static_cast<uint32_t>(
      (eip + totalSize) -
      (static_cast<uintptr_t>(originalOps - buf) +
       reinterpret_cast<uintptr_t>(hookDest)) -
      5);

  // Copy to target.
  WriteProcessMemory(process_.hProcess, hookDest, buf, 128, nullptr);
  FlushInstructionCache(process_.hProcess, hookDest, 128);

  // Install hook.
  buf[0] = 0xE9;
  *reinterpret_cast<uint32_t*>(buf + 1) = static_cast<uint32_t>(
      reinterpret_cast<uintptr_t>(hookDest) - eip - 5);
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(eip), buf, 5,
                     nullptr);
  FlushInstructionCache(process_.hProcess, reinterpret_cast<void*>(eip), 5);

  // Check if there's a jz/jnz that became invalid due to the hook and fix it.
  if (eip >= 9) {
    RPM(eip - 3 - 6, bytes, 6);
    if (bytes[0] == 0x0F && (bytes[1] == 0x84 || bytes[1] == 0x85)) {
      const uint32_t displacement =
          *reinterpret_cast<const uint32_t*>(bytes + 2);
      if (displacement >= 4 && displacement <= 7) {
        *reinterpret_cast<uint32_t*>(bytes + 2) = static_cast<uint32_t>(
            (reinterpret_cast<uintptr_t>(hookDest) + 0x37 +
             (displacement - 3)) -
            (eip - 3 - 6) - 6);
        WriteProcessMemory(process_.hProcess,
                           reinterpret_cast<void*>(eip - 3 - 4), bytes + 2, 4,
                           nullptr);
      }
    }
  }

  LogF(ltGood, "EFL Patch at %08llX",
       static_cast<unsigned long long>(eip));
  return true;
}

bool ThemidaDebugger::TMFinderCheck(CONTEXT* context) {
  uint16_t rep = 0;
  RPM(context->Eip, &rep, 2);
  if (rep == 0xA4F3) {
    return true;
  }

  const uintptr_t tmp = imageBase_ + 0x1000 + base1_ - 4;
  return context->Eax == tmp || context->Ebx == tmp || context->Ecx == tmp ||
         context->Edx == tmp || context->Esi == tmp || context->Edi == tmp;
}

// --------------------------------------------------------------------------
// Themida section handling
// --------------------------------------------------------------------------

void ThemidaDebugger::TMInit(HANDLE& hPE) {
  if (hPE == nullptr || hPE == INVALID_HANDLE_VALUE) {
    hPE = CreateFileW(executable_.c_str(), GENERIC_READ, FILE_SHARE_READ,
                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hPE == INVALID_HANDLE_VALUE) {
      throw std::runtime_error(
          Format("CreateFile code %lu", GetLastError()));
    }
  }

  SetFilePointer(hPE, 0, nullptr, FILE_BEGIN);

  uint8_t buffer[0x1000]{};
  DWORD bytesRead = 0;
  if (!ReadFile(hPE, buffer, sizeof(buffer), &bytesRead, nullptr)) {
    throw std::runtime_error(Format("ReadFile failed! Code: %lu", GetLastError()));
  }
  uint8_t* const bufferBase = buffer;
  const uint64_t ntOffset =
      static_cast<uint64_t>(reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_lfanew);
  if (ntOffset + sizeof(IMAGE_NT_HEADERS) > sizeof(buffer)) {
    throw std::runtime_error("Truncated NT headers");
  }
  uint8_t* const ntBase = buffer + ntOffset;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(ntBase);
  auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
      ntBase + sizeof(IMAGE_NT_HEADERS));
  const uint64_t sectionBytes =
      static_cast<uint64_t>(nt->FileHeader.NumberOfSections) *
      sizeof(IMAGE_SECTION_HEADER);
  if (reinterpret_cast<uint64_t>(sections) + sectionBytes >
      reinterpret_cast<uint64_t>(buffer) + sizeof(buffer)) {
    throw std::runtime_error("Truncated section table");
  }

  InitPEDetails(nt);

  if (peSections_.size() >= 2 &&
      peSections_.back().Misc.VirtualSize == 0x1000 &&
      peSections_.back().SizeOfRawData == 0x1000 &&
      peSections_[peSections_.size() - 2].Misc.VirtualSize == 0x1000) {
    themidaV2BySections_ = true;
  }

  baseOfData_ = nt->OptionalHeader.BaseOfData;
  compressed_ = peSections_[0].Misc.VirtualSize != peSections_[0].SizeOfRawData;
  base1_ = sections[0].Misc.VirtualSize;

  // PE header antidump.
  if (peSections_.size() < 3) {
    throw std::runtime_error("Unexpected PE layout (less than 3 sections)");
  }
  const uintptr_t test =
      reinterpret_cast<uintptr_t>(&sections[2].Name[0]) -
      reinterpret_cast<uintptr_t>(bufferBase) + imageBase_;
  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(test), 1,
                   PAGE_READWRITE, &oldProtect);
  uint32_t value = 'p';
  if (!WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(test),
                          &value, 1, nullptr)) {
    throw std::runtime_error(
        Format("Fixing PE header antidump failed! Code: %lu", GetLastError()));
  }

  if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
    const auto& tlsDirectory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_TLS_DIRECTORY32 tls{};
    if (RPM(imageBase_ + tlsDirectory.VirtualAddress, &tls,
            std::min<uint32_t>(tlsDirectory.Size, sizeof(tls)))) {
      // NOTE: This might be an MSVC-ism, where we assume the TLS callback
      // pointers are located right after the indexes. This allows us to
      // determine the amount of callbacks.
      const intptr_t tlsDistance =
          static_cast<intptr_t>(tls.AddressOfCallBacks) -
          static_cast<intptr_t>(tls.AddressOfIndex);
      if (tlsDistance > 0 && tlsDistance <= 4 * 4) {  // At most 4 TLS entries
        tlsTotal_ = static_cast<uint32_t>(tlsDistance / 4);
        tlsAddressesOfCallbacks_ = tls.AddressOfCallBacks;
        LogF(ltInfo, "Expecting up to %u TLS entries", tlsTotal_);
      }
    }
  }

  allocMemAPI_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwAllocateVirtualMemory"));
  allocHeapAPI_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAllocateHeap"));
}

void ThemidaDebugger::SelectThemidaSection(uintptr_t eip) {
  constexpr char kAncientName[8] = {'T', 'h', 'e', 'm', 'i', 'd', 'a', ' '};

  for (const IMAGE_SECTION_HEADER& section : peSections_) {
    if (eip >= section.VirtualAddress + imageBase_ &&
        eip < section.VirtualAddress + section.Misc.VirtualSize + imageBase_) {
      tmSectR_ = MemoryRegion(section.VirtualAddress + imageBase_,
                              section.Misc.VirtualSize);
      tmSectStorage_ = std::make_unique<uint8_t[]>(tmSectR_.Size);
      tmSect_ = tmSectStorage_.get();
      if (!RPM(tmSectR_.Address, tmSect_, tmSectR_.Size)) {
        tmSectStorage_.reset();
        tmSect_ = nullptr;
      }
      LogF(ltInfo, "TMSect: %llX (%zu bytes)",
           static_cast<unsigned long long>(tmSectR_.Address), tmSectR_.Size);
      if (std::memcmp(section.Name, kAncientName, 8) == 0) {
        ancientVer_ = true;
        Log(ltInfo, "Ancient Themida detected.");
      }
      break;
    }
  }

  if (tmSect_ == nullptr) {
    throw std::runtime_error("FATAL NO DATA");
  }
}

// --------------------------------------------------------------------------
// IAT fixing
// --------------------------------------------------------------------------

void ThemidaDebugger::TMIATFix(uintptr_t eip) {
  SelectThemidaSection(eip);
  TMIATFix2();
}

void ThemidaDebugger::TMIATFix2() {
  const uint32_t compareJumpsNew =
      FindDynamicTM("74??8B8D????????8B093B8D????????7410");
  if (compareJumpsNew == 0) {
    // Old Themida 1.x versions.
    const uint32_t cmpEax10000 = FindStaticTM("3D000001000F83");
    if (cmpEax10000 == 0) {
      Log(ltFatal, "\"cmp eax, 10000\" not found");
      return;
    }

    LogF(ltGood, "cmp eax, 10000 at %08X", cmpEax10000);

    const uint32_t magicJumpV1 =
        FindDynamicTM("3B8D????????0F84????0000", cmpEax10000);
    if (magicJumpV1 == 0) {
      Log(ltFatal, "First ImageBase compare jump not found");
      return;
    }

    magicJumpV1_ = reinterpret_cast<void*>(static_cast<uintptr_t>(magicJumpV1));
    SetBreakpoint(magicJumpV1, HWBPType::Execute);
  } else {
    LogF(ltGood, "ImageBase compare jumps found at: %08X", compareJumpsNew);
    cmpImgBase_ = reinterpret_cast<void*>(static_cast<uintptr_t>(compareJumpsNew));
    SetBreakpoint(compareJumpsNew, HWBPType::Execute);
  }
}

void ThemidaDebugger::TMIATFix3(uintptr_t eip) {
  if (eip == 0) {
    throw std::runtime_error("Cannot call TMIATFix3 with EIP=0");
  }

  uint32_t offset = static_cast<uint32_t>(eip - tmSectR_.Address);
  const uint32_t address = static_cast<uint32_t>(eip) +
                           FindDynamic("4B0F84????0000", tmSect_ + offset,
                                       tmSectR_.Size - offset);
  if (address == eip) {
    Log(ltFatal, "Magic jumps not found");
  } else {
    LogF(ltGood, "Magic jumps detected at: %08X", address);
    magicJump_ = reinterpret_cast<void*>(static_cast<uintptr_t>(address));
    SetBreakpoint(address, HWBPType::Execute);
  }
}

bool ThemidaDebugger::GetIATBPAddressNew(uintptr_t& result) {
  uintptr_t search = result;
  uint8_t byte = 0;

  for (;;) {
    const uint32_t found = FindDynamicTM("39??9C", search);
    if (found == 0) {
      result = 0;
      return false;
    }

    search = found;
    RPM(search - 1, &byte, 1);
    ++search;
    if (byte != 0x66) {
      break;
    }
  }

  result = search - 1;

  DISASM dis{};
  dis.EIP = reinterpret_cast<uintptr_t>(tmSect_) + (result - tmSectR_.Address);
  if (DisasmCheck(dis) != 2) {
    return false;  // instruction doesn't have a size of 2
  }

  if (result > mj1_) {
    return false;  // added for 213.2
  }

  result += 3;
  return true;
}

void ThemidaDebugger::TMIATFix4() {
  uintptr_t result = FindStaticTM("83F8500F82");
  if (result == 0) {
    throw std::runtime_error("\"cmp eax, 50\" not found");
  }

  LogF(ltGood, "cmp eax, 50 detected at: %08X", static_cast<uint32_t>(result));
  Log(ltGood, "[LCF-AT] Fixing IAT with the Fast IAT Patch Method.");

  result = FindDynamicTM("3985????????0F84");
  if (result == 0) {
    throw std::runtime_error("Not found");
  }

  const uintptr_t zech = result + 6;
  iJumper_ = zech;

  uintptr_t offset = result;
  result = FindStaticTM("2BD90F84", offset);
  if (result == 0) {
    result = FindStaticTM("29CB0F84", offset);
  }
  if (result == 0) {
    throw std::runtime_error("Both patterns not found");
  }

  mj2_ = result;
  const uintptr_t jumper =
      6 + mj2_ + 2 +
      *reinterpret_cast<const uint32_t*>(
          tmSect_ + (mj2_ + 4 - tmSectR_.Address));

  offset = result + 1;
  result = FindStaticTM("2BD90F84", offset);
  if (result == 0) {
    result = FindStaticTM("29CB0F84", offset);
  }
  if (result == 0) {
    throw std::runtime_error("Both patterns not found (2)");
  }

  mj3_ = result;
  const uintptr_t jumperX2 =
      6 + mj3_ + 2 +
      *reinterpret_cast<const uint32_t*>(
          tmSect_ + (mj3_ + 4 - tmSectR_.Address));
  if (jumper != jumperX2) {
    throw std::runtime_error("Old magic jump");
  }

  offset = result + 1;
  result = FindStaticTM("2BD90F84", offset);
  if (result == 0) {
    result = FindStaticTM("29CB0F84", offset);
  }
  if (result == 0) {
    throw std::runtime_error("Both patterns not found (3)");
  }

  mj4_ = result;
  offset = mj2_;

  while (offset > tmSectR_.Address &&
         (*reinterpret_cast<const uint16_t*>(
              tmSect_ + (offset - tmSectR_.Address)) != 0x840F ||
          6 + offset +
                  *reinterpret_cast<const uint32_t*>(
                      tmSect_ + (offset + 2 - tmSectR_.Address)) !=
              jumper)) {
    --offset;
  }

  if (*reinterpret_cast<const uint16_t*>(
          tmSect_ + (offset - tmSectR_.Address)) != 0x840F ||
      6 + offset +
              *reinterpret_cast<const uint32_t*>(
                  tmSect_ + (offset + 2 - tmSectR_.Address)) !=
          jumper) {
    throw std::runtime_error("Magic jump 1 not found");
  }

  mj1_ = offset;
  LogF(ltInfo, "MJ1 %08llX", static_cast<unsigned long long>(mj1_));
  LogF(ltInfo, "MJ2 %08llX", static_cast<unsigned long long>(mj2_));
  LogF(ltInfo, "MJ3 %08llX", static_cast<unsigned long long>(mj3_));
  LogF(ltInfo, "MJ4 %08llX", static_cast<unsigned long long>(mj4_));

  uint8_t b1 = 0;
  uint8_t b2 = 0;
  uint8_t b3 = 0;
  uint8_t b4 = 0;
  RPM(mj1_ - 1, &b1, 1);
  RPM(mj2_, &b2, 1);
  RPM(mj3_, &b3, 1);
  RPM(mj4_, &b4, 1);
  if (((b1 != 0x4B) || (b2 != 0x2B) || (b3 != 0x2B) || (b4 != 0x2B)) &&
      (b2 != 0x29)) {
    newVer_ = false;
  } else {
    newVer_ = true;
  }

  if (FindDynamicTM(
          "68????????E9??????FF68????????E9??????FF68????????E9??????FF") !=
      0) {
    newVer_ = false;
  }
  if (FindDynamicTM(
          "68????????68????????E9??????FF68????????68????????E9??????FF") !=
      0) {
    newVer_ = true;
  }

  if (!newVer_) {
    Log(ltInfo, "Older Themida version found.");
  } else {
    Log(ltInfo, "Newer Themida version found.");
  }

  // NEW_RISC = 1, WL_IS_NEW = 1
  result = FindStaticTM("3BC89CE9");
  if (result == 0) {
    result = tmSectR_.Address;
    bool valid = GetIATBPAddressNew(result);
    while (result != 0) {
      if (valid) {
        LogF(ltInfo, "SetSoft: %08llX",
             static_cast<unsigned long long>(result));
        SetSoftBP(result);
      }

      result += 2;
      valid = GetIATBPAddressNew(result);
    }
    // SP_WAS_SET = 1, SP_NEW_USE = 1
  } else {
    do {
      result += 3;
      LogF(ltInfo, "SetSoft : %08llX",
           static_cast<unsigned long long>(result));
      SetSoftBP(result);
      result = FindStaticTM("3BC89CE9", result);
    } while (result != 0);
  }

  // Monitor code section for write accesses (tampering with API call sites,
  // old Themida versions only). The collected addresses are processed in
  // FinishUnpacking/FixupAPICallSites.
  InstallCodeSectionGuard(PAGE_READONLY);  // Performance optimization.

  SetBreakpoint(mj1_, HWBPType::Execute);
}

void ThemidaDebugger::TMIATFix5(uintptr_t eax) {
  LogF(ltInfo, "First API in eax: %08llX",
       static_cast<unsigned long long>(eax));

  uint64_t buf = 0xE990;
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(iJumper_), &buf,
                     2, nullptr);
  buf = 0x909090909090;
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(mj1_), &buf, 6,
                     nullptr);
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(mj2_ + 2), &buf,
                     6, nullptr);
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(mj3_ + 2), &buf,
                     6, nullptr);
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(mj4_ + 2), &buf,
                     6, nullptr);
  FlushInstructionCache(process_.hProcess, reinterpret_cast<void*>(mj1_), 6);
  LogF(ltGood, "IAT Jumper was found & fixed at %llX",
       static_cast<unsigned long long>(iJumper_));
}

void ThemidaDebugger::TMIATFixThemidaV1(uintptr_t baseCompare1) {
  const uintptr_t baseCompare2 =
      FindDynamicTM("3B8D????????0F84????0000", baseCompare1 + 12);
  if (baseCompare2 == 0) {
    throw std::runtime_error("[Themida 1.x] BaseCompare2 not found");
  }

  const uintptr_t baseCompare3 =
      FindDynamicTM("3B8D????????0F84????0000", baseCompare2 + 12);
  if (baseCompare3 == 0) {
    throw std::runtime_error("[Themida 1.x] BaseCompare3 not found");
  }

  iJumper_ = FindDynamicTM("3985????????0F84");
  if (iJumper_ == 0) {
    throw std::runtime_error("[Themida 1.x] IAT jumper not found");
  }

  LogF(ltInfo, "BC1 %llX", static_cast<unsigned long long>(baseCompare1));
  LogF(ltInfo, "BC2 %llX", static_cast<unsigned long long>(baseCompare2));
  LogF(ltInfo, "BC3 %llX", static_cast<unsigned long long>(baseCompare3));

  // This is required so Themida doesn't end the process when BaseCompare
  // patches are in place.
  uint64_t buf = 0xE990;
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(iJumper_ + 6), &buf, 2, nullptr);
  // These prevent IAT wrapping, which only happens for the three modules
  // kernel32, user32 and advapi32.
  buf = 0x909090909090;
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(baseCompare1 + 6), &buf, 6,
                     nullptr);
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(baseCompare2 + 6), &buf, 6,
                     nullptr);
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(baseCompare3 + 6), &buf, 6,
                     nullptr);

  LogF(ltGood, "IAT Jumper was found & fixed at %llX",
       static_cast<unsigned long long>(iJumper_));

  guardStart_ = imageBase_ + peSections_[0].VirtualAddress;
  guardEnd_ = imageBase_ + 0x100000;
  guardProtection_ = PAGE_NOACCESS;
  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guardStart_),
                   guardEnd_ - guardStart_, guardProtection_, &oldProtect);
}

// --------------------------------------------------------------------------
// Code section guard
// --------------------------------------------------------------------------

void ThemidaDebugger::InstallCodeSectionGuard(uint32_t protection) {
  guardStart_ = imageBase_ + peSections_[0].VirtualAddress;
  guardEnd_ = imageBase_ + baseOfData_;
  guardProtection_ = protection;
  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guardStart_),
                   guardEnd_ - guardStart_, guardProtection_, &oldProtect);

  if (!themidaV3_ &&
      !IsHWBreakpoint(reinterpret_cast<uintptr_t>(virtualProtectAPI_))) {
    SetBreakpoint(reinterpret_cast<uintptr_t>(virtualProtectAPI_));
  }
}

bool ThemidaDebugger::IsGuardedAddress(uintptr_t address) {
  if (guardStart_ == 0) {
    return false;
  }
  return address >= guardStart_ && address < guardEnd_;
}

DWORD ThemidaDebugger::ProcessGuardedAccess(
    HANDLE hThread, const EXCEPTION_RECORD& exceptionRecord) {
  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guardStart_),
                   guardEnd_ - guardStart_, PAGE_EXECUTE_READWRITE, &oldProtect);

  const auto handleOEP = [&]() {
    uintptr_t oep = reinterpret_cast<uintptr_t>(exceptionRecord.ExceptionAddress);
    LogF(ltGood, "OEP: %08llX", static_cast<unsigned long long>(oep));

    RestoreStolenOEPForMSVC6(hThread, oep);
    if (isDll_ && majorLinkerVersion_ == 9) {
      RestoreStolenOEPForMSVC9DLL(hThread, oep);
    }
    CheckVirtualizedOEP(oep);

    if (!ancientVer_) {
      // Check if virtualized and stolen (goes straight into VM without using
      // jmp in .text).
      CONTEXT context{};
      context.ContextFlags = CONTEXT_CONTROL;
      if (GetThreadContext(hThread, &context)) {
        uint32_t returnAddress = 0;
        RPM(context.Esp, &returnAddress, 4);
        if (tmSectR_.Contains(returnAddress) &&
            !IsTMExceptionHandler(returnAddress)) {
          LogF(ltInfo, "OEP return address points into Themida section: %.8X",
               returnAddress);
          oep = TryFindCorrectOEP(oep);
        }
      } else {
        Log(ltFatal, "GetThreadContext failed for further OEP check");
      }
    }

    FinishUnpacking(oep);
  };

  if (reinterpret_cast<uintptr_t>(exceptionRecord.ExceptionAddress) >
      guardEnd_) {
    guardAddrs_.push_back(exceptionRecord.ExceptionInformation[1]);
    // Single-step, then re-protect in OnHardwareBreakpoint.
    guardStepping_ = true;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &context)) {
      throw std::runtime_error(
          Format("GetThreadContext failed (error %lu)", GetLastError()));
    }
    context.EFlags |= 0x100;
    SetThreadContext(hThread, &context);
  } else if (tlsTotal_ > 0 && tlsCounter_ < tlsTotal_) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &context)) {
      uint32_t returnAddress = 0;
      uint32_t args[3]{};
      RPM(context.Esp, &returnAddress, 4);
      RPM(context.Esp + 4, args, 12);
      if (tmSectR_.Contains(returnAddress) &&
          !IsTMExceptionHandler(returnAddress) && ((args[0] & 0xFFF) == 0) &&
          args[1] <= 3) {
        ++tlsCounter_;
        LogF(ltGood, "TLS %u: %.8X (%X, %X, %X)", tlsCounter_,
             static_cast<uint32_t>(
                 reinterpret_cast<uintptr_t>(exceptionRecord.ExceptionAddress)),
             args[0], args[1], args[2]);
        // Skip execution, we want nothing initialized in the unpacked binary.
        context.Eip = returnAddress;
        context.Esp += 4 + 3 * 4;
        SetThreadContext(hThread, &context);
        InstallCodeSectionGuard(guardProtection_);
      } else {
        LogF(ltInfo,
             "This doesn't look like TLS (ret %X; args %X, %X, %X), assuming "
             "OEP.",
             returnAddress, args[0], args[1], args[2]);
        handleOEP();
      }
    } else {
      Log(ltFatal, "GetThreadContext failed for TLS check");
      handleOEP();
    }
  } else {
    handleOEP();
  }

  return DBG_CONTINUE;
}

// --------------------------------------------------------------------------
// OEP restoration
// --------------------------------------------------------------------------

void ThemidaDebugger::RestoreStolenOEPForMSVC6(HANDLE hThread, uintptr_t& oep) {
  constexpr uint8_t kRestoreData[] = {
      0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0, 0, 0,
      0,    0x68, 0,    0,    0,    0,    0x64, 0xA1, 0x00,
      0x00, 0x00, 0x00, 0x50, 0x64, 0x89, 0x25, 0x00, 0x00,
      0x00, 0x00, 0x83, 0xEC, 0x58, 0x53, 0x56, 0x57, 0x89,
      0x65, 0xE8, 0xFF, 0x15, 0,    0,    0,    0,    0x33,
      0xD2,
  };
  constexpr size_t kRestoreSize = sizeof(kRestoreData);

  uint8_t checkBuffer[3]{};
  RPM(oep, checkBuffer, 2);

  // mov dl, ah
  if (checkBuffer[0] != 0x8A || checkBuffer[1] != 0xD4) {
    return;  // not MSVC6 or not stolen
  }

  Log(ltInfo, "Stolen MSVC6 OEP detected.");

  RPM(oep - kRestoreSize - 3, checkBuffer, 3);
  if (checkBuffer[0] != 0xC2 && checkBuffer[2] != 0xC3) {
    Log(ltFatal, "Stolen OEP gap mismatch.");
    return;
  }

  std::array<uint8_t, kRestoreSize> restoreData{};
  std::memcpy(restoreData.data(), kRestoreData, kRestoreSize);
  oep -= kRestoreSize;

  const uintptr_t getVersionAddress = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetVersion"));

  const uintptr_t iat = imageBase_ + baseOfData_;

  std::vector<uintptr_t> iatData(512);
  RPM(iat, iatData.data(), iatData.size() * sizeof(uintptr_t));
  for (size_t i = 0; i < iatData.size(); ++i) {
    if (iatData[i] == getVersionAddress) {
      *reinterpret_cast<uint32_t*>(restoreData.data() + kRestoreSize - 6) =
          static_cast<uint32_t>(iat + i * 4);
      break;
    }
  }

  if (*reinterpret_cast<uint32_t*>(restoreData.data() + kRestoreSize - 6) ==
      0) {
    Log(ltFatal, "Unable to find GetVersion in IAT.");
    return;
  }

  CONTEXT context{};
  context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
  if (!GetThreadContext(hThread, &context)) {
    throw std::runtime_error(
        Format("GetThreadContext failed (error %lu)", GetLastError()));
  }

  if (context.Esp != context.Ebp - 0x74) {
    LogF(ltFatal, "Stack frame mismatch: esp=%x, ebp=%x", context.Esp,
         context.Ebp);
    return;
  }

  uintptr_t stackData[2]{};
  RPM(context.Ebp - 3 * sizeof(uintptr_t), stackData, sizeof(stackData));

  *reinterpret_cast<uint32_t*>(restoreData.data() + 6) =
      static_cast<uint32_t>(stackData[1]);
  *reinterpret_cast<uint32_t*>(restoreData.data() + 11) =
      static_cast<uint32_t>(stackData[0]);

  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(oep),
                     restoreData.data(), kRestoreSize, nullptr);

  LogF(ltGood, "Correct OEP: %08llX", static_cast<unsigned long long>(oep));
}

void ThemidaDebugger::RestoreStolenOEPForMSVC9DLL(HANDLE /*hThread*/,
                                                   uintptr_t& oep) {
  constexpr uint8_t kRestoreData[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83,
                                      0x7D, 0x0C, 0x01, 0x75, 0x05};

  uint8_t checkByte = 0;
  RPM(oep, &checkByte, 1);
  if (checkByte != 0xE8) {
    return;
  }

  RPM(oep - sizeof(kRestoreData), &checkByte, 1);
  if (checkByte != 0xE9) {  // jmp to vm
    return;
  }

  Log(ltInfo, "Stolen MSVC9 DLL OEP detected.");

  oep -= sizeof(kRestoreData);
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(oep),
                     kRestoreData, sizeof(kRestoreData), nullptr);

  LogF(ltGood, "Correct OEP: %08llX", static_cast<unsigned long long>(oep));
}

uintptr_t ThemidaDebugger::TryFindCorrectOEP(uintptr_t oep) {
  uintptr_t result = oep;
  if (majorLinkerVersion_ != 9 && majorLinkerVersion_ != 10 &&
      majorLinkerVersion_ != 11 && majorLinkerVersion_ != 12 &&
      majorLinkerVersion_ != 14) {
    Log(ltFatal,
        "Don't know what to do about OEP for this compiler. Your target "
        "likely won't run.");
    return result;
  }

  // MSVC: Assume current (wrong) OEP is at __security_init_cookie.
  // Scan for call __security_init_cookie; jmp __scrt_common_main_seh
  const uint32_t textLen =
      static_cast<uint32_t>(baseOfData_ - peSections_[0].VirtualAddress);
  std::vector<uint8_t> textBuffer(textLen);
  {
    RPM(imageBase_ + peSections_[0].VirtualAddress, textBuffer.data(),
        textBuffer.size());

    const uint32_t scanFor = static_cast<uint32_t>(
        oep - imageBase_ - peSections_[0].VirtualAddress);
    for (uint32_t i = 0; i + 10 <= textLen; ++i) {
      if (textBuffer[i] == 0xE8 && textBuffer[i + 5] == 0xE9 &&
          *reinterpret_cast<const uint32_t*>(textBuffer.data() + i + 1) + i +
                  5 ==
              scanFor) {
        result = imageBase_ + peSections_[0].VirtualAddress + i;
        LogF(ltGood, "Found likely real OEP %.8llX",
             static_cast<unsigned long long>(result));
        return result;
      }
    }

    Log(ltFatal, "Real OEP not found. Your target likely won't run.");
  }

  return result;
}

bool ThemidaDebugger::IsTMExceptionHandler(uintptr_t address) {
  uint8_t data[64]{};
  RPM(address, data, sizeof(data));

  for (size_t i = 0; i < 60; ++i) {
    if (*reinterpret_cast<const uint32_t*>(data + i) == 0x00B8838B) {
      // mov eax, [ebx+CONTEXT._Eip]
      return true;
    }
  }

  return false;
}

void ThemidaDebugger::FixupAPICallSites(uintptr_t iat) {
  std::sort(guardAddrs_.begin(), guardAddrs_.end());

  std::vector<uintptr_t> siteSet;
  siteSet.push_back(guardAddrs_[0]);
  for (size_t i = 1; i < guardAddrs_.size(); ++i) {
    if (guardAddrs_[i] >= siteSet.back() + 6) {
      siteSet.push_back(guardAddrs_[i]);
    }
  }

  LogF(ltInfo, "Deduced %zu call sites from %zu accesses", siteSet.size(),
       guardAddrs_.size());

  std::vector<uintptr_t> iatData(MAX_IAT_SIZE / sizeof(uintptr_t));
  RPM(iat, iatData.data(), iatData.size() * sizeof(uintptr_t));

  std::unordered_map<uintptr_t, uintptr_t> iatMap;
  for (size_t i = 0; i < iatData.size(); ++i) {
    iatMap[iatData[i]] = iat + i * 4;
  }

  bool isJmp = false;
  uintptr_t target = 0;

  for (uintptr_t siteAddress : siteSet) {
    uint8_t site[6]{};
    RPM(siteAddress, site, 6);
    if (site[0] == 0xE8 || site[0] == 0xE9) {
      target = *reinterpret_cast<const uint32_t*>(site + 1) + siteAddress + 5;
      isJmp = site[0] == 0xE9;
    } else if (site[1] == 0xE8 || site[1] == 0xE9) {
      target = *reinterpret_cast<const uint32_t*>(site + 2) + siteAddress + 6;
      isJmp = site[1] == 0xE9;
    } else {
      if (site[0] != 0xFF || (site[1] != 0x15 && site[1] != 0x25)) {
        LogF(ltFatal,
             "Unknown call site at %llX: %02X %02X %02X %02X %02X %02X",
             static_cast<unsigned long long>(siteAddress), site[0], site[1],
             site[2], site[3], site[4], site[5]);
      }
      continue;
    }

    const auto it = iatMap.find(target);
    if (it == iatMap.end()) {
      LogF(ltFatal, "Not in IAT: %llX (from %llX)",
           static_cast<unsigned long long>(target),
           static_cast<unsigned long long>(siteAddress));
      continue;
    }

    // Turn the relative call/jmp into call/jmp dword ptr [iat]
    site[0] = 0xFF;
    site[1] = static_cast<uint8_t>(0x15 + (isJmp ? 0x10 : 0x00));
    *reinterpret_cast<uint32_t*>(site + 2) = static_cast<uint32_t>(it->second);
    WriteProcessMemory(process_.hProcess,
                       reinterpret_cast<void*>(siteAddress), site, 6, nullptr);
  }
}

void ThemidaDebugger::FinishUnpacking(uintptr_t oep) {
  // Remove EFL jumps from VM code.
  for (EFLRecord& efl : efls_) {
    if (efl.Address == 0) {
      break;
    }
    WriteProcessMemory(process_.hProcess,
                       reinterpret_cast<void*>(efl.Address),
                       efl.Original.data(), efl.Original.size(), nullptr);
  }

  Dumper dumper(process_, executable_, imageBase_, oep);

  // Look for IAT by analyzing code near OEP.
  const uintptr_t iat = DetermineIATAddress(oep, dumper);
  LogF(ltGood, "IAT: %08llX", static_cast<unsigned long long>(iat));

  // Themida v3: Weak traceable import protection.
  if (themidaV3_) {
    // Import addresses are protected with a simple xor+subtraction scheme.
    // The values are different for each address slot - they're held in a big
    // table somewhere in the TM section. The entire code that does these
    // computations and stores the address is virtualized. There is no runtime
    // decision not to do this like there was before (with
    // kernel32/advapi32/user32 bases), so we can't patch it out.
    TraceImports(iat, dumper);
  }

  // Old Themida versions like turning API calls into relative calls/jumps -
  // restore them to absolute references to the IAT.
  if (!guardAddrs_.empty()) {
    FixupAPICallSites(iat);
  }

  if (isVMOEP_ && themidaV3_) {
    AntiDumpFixer fixer(process_.hProcess, imageBase_);
    fixer.RedirectOEP(oep, iat);
  }

  // Process the IAT into an import directory and dump the binary to disk.
  const std::wstring fileName = MakeUnpackedFileName(executable_);
  dumper.IAT = iat;
  auto pe = dumper.Process();
  dumper.DumpToFile(fileName, *pe, isDll_);
  LogF(ltGood, "Dump written to: %s", WideToUtf8(fileName).c_str());

  hideThreadEnd_ = true;
  TerminateProcess(process_.hProcess, 0);

  if (createDataSections_) {
    Patcher patcher(fileName);
    if (!patcher.ProcessMkData()) {
      Log(ltWarning, "Data sections were not created.");
    }
  }

  if (fixRelocations_) {
    if (isDll_) {
      try {
        FixDllRelocations(fileName, imageBase_);
      } catch (const std::exception& error) {
        LogF(ltWarning, "Relocation fix failed: %s", error.what());
      }
    } else {
      Log(ltWarning, "The relocation fix is only applied to DLL targets.");
    }
  }

  MarkSuccess();
  Log(ltGood, "Operation completed successfully.");
}

// --------------------------------------------------------------------------
// Tracing
// --------------------------------------------------------------------------

bool ThemidaDebugger::TraceIsAtAPI(Tracer& tracer, CONTEXT& context) {
  if (tracer.Counter() > 100 && tracer.Counter() < 5000) {
    uint32_t insnData = 0;
    RPM(context.Eip, &insnData, 4);
    if (insnData == 0x4CB10FF0) {
      // First 4 bytes of "lock cmpxchg [ebp+ebx+0], ecx"
      traceInVM_ = true;
      Log(ltInfo, "Trace ran into Themida VM, stopping");
      return true;  // Stop
    }
  }

  // Cat & mouse game with fake calls.
  if (context.Esp < traceStartSP_ &&
      (context.Eip == sleepAPI_ || context.Eip == lstrlenAPI_)) {
    // It'd be better to just execute them, but the tracer currently faults at
    // far jumps for wow64 syscalls.
    LogF(ltInfo, "Skipping anti-trace API at %.8x", context.Eip);
    uint32_t returnAddress = 0;
    RPM(context.Esp, &returnAddress, 4);
    context.Esp += 8;
    context.Eip = returnAddress;
  }

  bool result = !tmSectR_.Contains(context.Eip);
  if (result && context.Esp < traceStartSP_) {
    LogF(ltInfo, "Warning: Might have encountered new fake API at %.8x",
         context.Eip);
    result = false;
  }

  if (result) {
    tracedAPI_ = context.Eip;
  }
  return result;
}

}  // namespace magicmida
