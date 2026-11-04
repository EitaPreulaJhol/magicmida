// Magicmida - C++ port
// 64-bit Themida/WinLicense unpacking logic (ported from Themida64.pas).
#include "themida64.h"

#include "pe_report.h"
#include "reloc_fix.h"
#include "scyllahide.h"

#include <algorithm>
#include <cstring>

namespace magicmida {
namespace {

std::string SectionNameTrimmed(const IMAGE_SECTION_HEADER& header) {
  char name[9]{};
  std::memcpy(name, header.Name, 8);
  return std::string(name);
}

}  // namespace

ThemidaDebugger64::ThemidaDebugger64(const std::wstring& executable,
                                     const std::wstring& parameters,
                                     bool createData, bool useScyllaHide,
                                     bool fixRelocations)
    : ThemidaCommon(executable, parameters) {
  createDataSections_ = createData;  // Currently does nothing.
  useScyllaHide_ = useScyllaHide;
  fixRelocations_ = fixRelocations;
  themidaV3_ = true;                 // Themida V2 is not supported on x64 atm.
}

bool ThemidaDebugger64::InImageBounds(uintptr_t address) const {
  return address >= imageBase_ && address < imageBoundary_;
}

// --------------------------------------------------------------------------
// Debugger hooks
// --------------------------------------------------------------------------

void ThemidaDebugger64::SelectThemidaSection(uintptr_t address) {
  for (const IMAGE_SECTION_HEADER& section : peSections_) {
    if (address >= section.VirtualAddress + imageBase_ &&
        address < section.VirtualAddress + section.Misc.VirtualSize +
                      imageBase_) {
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
      break;
    }
  }

  if (tmSect_ == nullptr) {
    throw std::runtime_error(
        Format("Unable to find section for %llX",
               static_cast<unsigned long long>(address)));
  }
}

void ThemidaDebugger64::OnDebugStart(HANDLE& hPE, HANDLE hThread) {
  if (useScyllaHide_) {
    std::string scyllaError;
    if (!scyllahide::Start(process_.hProcess, process_.dwProcessId,
                           scyllahide::DefaultProfile(), &scyllaError)) {
      throw std::runtime_error("ScyllaHide injection failed: " + scyllaError);
    }
    LogF(ltGood, "Applying embedded ScyllaHide (%s)",
         scyllahide::Version());
  } else {
    Log(ltWarning,
        "ScyllaHide disabled by the Disable ScyllaHide option; Themida64 may "
        "detect the debugger");
  }

  virtualAllocAPI_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualAlloc"));

  sleepAPI_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep"));
  lstrlenAPI_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "lstrlen"));

  TMInit(hPE);
}

DWORD ThemidaDebugger64::OnAccessViolation(
    HANDLE hThread, const EXCEPTION_RECORD& exceptionRecord) {
  if (IsGuardedAddress(exceptionRecord.ExceptionInformation[1])) {
    return ProcessGuardedAccess(hThread, exceptionRecord);
  }
  return ThemidaCommon::OnAccessViolation(hThread, exceptionRecord);
}

void ThemidaDebugger64::OnDLLLoad(const std::wstring& fileName,
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

void ThemidaDebugger64::OnHardwareBreakpoint(HANDLE /*hThread*/,
                                             uintptr_t bpAddress,
                                             CONTEXT& context) {
  const uintptr_t eip = context.Rip;

  if (eip == reinterpret_cast<uintptr_t>(closeHandleAPI_)) {
    uintptr_t buf = 0;
    RPM(context.Rsp, &buf, 8);

    LogF(ltInfo, "CloseHandle called from from %p",
         reinterpret_cast<void*>(buf));

    if (InImageBounds(buf)) {
      ResetBreakpoint(eip);
      SetBreakpoint(imageBase_ + 0x1000, HWBPType::Write);
    }
  } else if (eip == reinterpret_cast<uintptr_t>(virtualAllocAPI_)) {
    uintptr_t buf = 0;
    RPM(context.Rsp, &buf, 8);
    LogF(ltInfo, "AllocMem called from %llX",
         static_cast<unsigned long long>(buf));

    if (InImageBounds(buf)) {
      ResetBreakpoint(reinterpret_cast<uintptr_t>(virtualAllocAPI_));
      InstallCodeSectionGuard();
    }
  } else if (bpAddress == imageBase_ + 0x1000) {
    LogF(ltGood, "Wrote to .text base from %llX",
         static_cast<unsigned long long>(eip));

    if (tmSectR_.Address == 0) {
      SelectThemidaSection(eip);
    }

    ResetBreakpoint(imageBase_ + 0x1000);
    SetBreakpoint(reinterpret_cast<uintptr_t>(virtualAllocAPI_),
                  HWBPType::Execute);
  } else {
    LogF(ltInfo, "Accessed %llx from %p",
         static_cast<unsigned long long>(bpAddress),
         reinterpret_cast<void*>(eip));
  }
}

DWORD ThemidaDebugger64::OnSinglestep(uintptr_t bpAddress) {
  if (guardStepping_) {
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(process_.hProcess,
                          reinterpret_cast<void*>(guardStart_),
                          guardEnd_ - guardStart_, PAGE_NOACCESS,
                          &oldProtect)) {
      throw std::runtime_error(
          Format("VirtualProtectEx failed (error %lu)", GetLastError()));
    }
    guardStepping_ = false;
    return DBG_CONTINUE;
  }

  return ThemidaCommon::OnSinglestep(bpAddress);
}

SoftBPAction ThemidaDebugger64::OnSoftwareBreakpoint(HANDLE /*hThread*/,
                                                     uintptr_t bpAddress) {
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

  throw std::runtime_error(
      Format("Unexpected SoftBP at %p", reinterpret_cast<void*>(bpAddress)));
}

void ThemidaDebugger64::DumpContext(DWORD threadId) {
  HANDLE hThread = GetThread(threadId);
  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  if (!GetThreadContext(hThread, &context)) {
    Log(ltFatal, "DumpContext: GetThreadContext failed");
    return;
  }

  LogF(ltInfo, "rax: %llX rbx: %llX rcx: %llX rdx: %llX rsi: %llX rdi: %llX",
       static_cast<unsigned long long>(context.Rax),
       static_cast<unsigned long long>(context.Rbx),
       static_cast<unsigned long long>(context.Rcx),
       static_cast<unsigned long long>(context.Rdx),
       static_cast<unsigned long long>(context.Rsi),
       static_cast<unsigned long long>(context.Rdi));
  LogF(ltInfo,
       "r8: %llX r9: %llX r10: %llX r11: %llX r12: %llX r13: %llX r14: %llX "
       "r15: %llX",
       static_cast<unsigned long long>(context.R8),
       static_cast<unsigned long long>(context.R9),
       static_cast<unsigned long long>(context.R10),
       static_cast<unsigned long long>(context.R11),
       static_cast<unsigned long long>(context.R12),
       static_cast<unsigned long long>(context.R13),
       static_cast<unsigned long long>(context.R14),
       static_cast<unsigned long long>(context.R15));
  LogF(ltInfo, "rip: %llX rbp: %llX rsp: %llX eflags: %lX",
       static_cast<unsigned long long>(context.Rip),
       static_cast<unsigned long long>(context.Rbp),
       static_cast<unsigned long long>(context.Rsp),
       static_cast<unsigned long>(context.EFlags));
}

// --------------------------------------------------------------------------
// Themida section handling
// --------------------------------------------------------------------------

void ThemidaDebugger64::TMInit(HANDLE& hPE) {
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
    throw std::runtime_error(
        Format("ReadFile failed! Code: %lu", GetLastError()));
  }

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

  if (peSections_.size() < 3) {
    throw std::runtime_error("Unexpected PE layout (less than 3 sections)");
  }

  baseOfData_ = sections[0].VirtualAddress + nt->OptionalHeader.SizeOfCode;

  // PE header antidump.
  if (sections[2].Name[0] == 'i') {
    const uintptr_t test =
        reinterpret_cast<uintptr_t>(&sections[2].Name[0]) -
        reinterpret_cast<uintptr_t>(buffer) + imageBase_;
    DWORD oldProtect = 0;
    VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(test), 1,
                     PAGE_READWRITE, &oldProtect);
    uint32_t value = 'p';
    if (!WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(test),
                            &value, 1, nullptr)) {
      throw std::runtime_error(
          Format("Fixing PE header antidump failed! Code: %lu",
                 GetLastError()));
    }
  }

  if (SectionNameTrimmed(sections[0]) == ".text") {
    // Code not encrypted/compressed.
    Log(ltGood, "Text section not encrypted/compressed, installing page guard");
    InstallCodeSectionGuard();
  } else {
    closeHandleAPI_ = reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CloseHandle"));
    SetBreakpoint(reinterpret_cast<uintptr_t>(closeHandleAPI_),
                  HWBPType::Execute);
  }

  if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
    const auto& tlsDirectory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_TLS_DIRECTORY64 tls{};
    if (RPM(imageBase_ + tlsDirectory.VirtualAddress, &tls,
            std::min<uint32_t>(tlsDirectory.Size, sizeof(tls)))) {
      // NOTE: This is an MSVC-ism, where we assume the TLS callback pointers
      // are located right before the TLS directory. This allows us to
      // determine the amount of callbacks.
      const intptr_t tlsDistance =
          static_cast<intptr_t>(imageBase_ + tlsDirectory.VirtualAddress) -
          static_cast<intptr_t>(tls.AddressOfCallBacks);
      if (tlsDistance > 0 &&
          tlsDistance <= static_cast<intptr_t>(sizeof(uintptr_t) * (4 + 1))) {
        // Assume at most 4 TLS entries + zero terminator.
        tlsTotal_ = static_cast<uint32_t>(tlsDistance / sizeof(uintptr_t)) - 1;
        LogF(ltInfo, "[MSVC] Expecting %u TLS entries", tlsTotal_);
      }
    }
  }
}

// --------------------------------------------------------------------------
// Code section guard
// --------------------------------------------------------------------------

void ThemidaDebugger64::InstallCodeSectionGuard() {
  guardStart_ = imageBase_ + peSections_[0].VirtualAddress;
  guardEnd_ = imageBase_ + baseOfData_;
  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guardStart_),
                   guardEnd_ - guardStart_, PAGE_NOACCESS, &oldProtect);
}

bool ThemidaDebugger64::IsGuardedAddress(uintptr_t address) {
  if (guardStart_ == 0) {
    return false;
  }
  return address >= guardStart_ && address < guardEnd_;
}

DWORD ThemidaDebugger64::ProcessGuardedAccess(
    HANDLE hThread, const EXCEPTION_RECORD& exceptionRecord) {
  LogF(ltInfo, "[Guard] %s %llX",
       AccessViolationFlagToStr(
           static_cast<uint8_t>(exceptionRecord.ExceptionInformation[0]))
           .c_str(),
       static_cast<unsigned long long>(exceptionRecord.ExceptionInformation[1]));

  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guardStart_),
                   guardEnd_ - guardStart_, PAGE_EXECUTE_READWRITE, &oldProtect);

  const uintptr_t exceptionAddress =
      reinterpret_cast<uintptr_t>(exceptionRecord.ExceptionAddress);

  if (tmGuard_) {
    // We've hit the Themida section after executing a TLS entrypoint.
    tmGuard_ = false;
    InstallCodeSectionGuard();
  } else if (!InImageBounds(exceptionAddress)) {
    // Random library code reading our text base...
    guardStepping_ = true;
  } else if (exceptionAddress > guardEnd_) {
    // Themida access.
    if (tmSectR_.Address == 0) {
      SelectThemidaSection(exceptionAddress);
    }

    guardAddrs_.push_back(exceptionRecord.ExceptionInformation[1]);
    guardStepping_ = true;
  } else if (exceptionRecord.ExceptionInformation[0] == 8 && tlsTotal_ > 0 &&
             tlsCounter_ < tlsTotal_) {
    ++tlsCounter_;
    LogF(ltGood, "TLS %u: %.9llX", tlsCounter_,
         static_cast<unsigned long long>(exceptionAddress));
    guardStart_ = tmSectR_.Address;
    guardEnd_ = imageBoundary_;
    tmGuard_ = true;
    // Allow R/W, disallow execute. Some weird binaries read a byte at the PE's
    // AddressOfEntryPoint in TLS...
    VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guardStart_),
                     guardEnd_ - guardStart_, PAGE_READWRITE, &oldProtect);
  } else if (traceMSVCOEP_) {
    // We're at mainCrtStartup.
    WriteMSVCOEP(exceptionAddress);
    FinishUnpacking(msvcOEP_);
  } else {
    uintptr_t oep = exceptionAddress;

    // Check if virtualized (but goes to .text first for jmp).
    CheckVirtualizedOEP(oep);

    // Check if virtualized and stolen (goes straight into VM without using jmp
    // in .text).
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &context)) {
      uintptr_t returnAddress = 0;
      RPM(context.Rsp, &returnAddress, 8);
      if (tmSectR_.Contains(returnAddress)) {
        LogF(ltInfo, "Return address points into Themida section: %.9llX",
             static_cast<unsigned long long>(returnAddress));
        oep = TryFindCorrectOEP(oep);

        if (traceMSVCOEP_) {
          msvcOEP_ = oep;

          // Skip and wait for next .text hit.
          context.Rip = returnAddress;
          context.Rsp += 8;
          if (!SetThreadContext(hThread, &context)) {
            throw std::runtime_error(
                Format("SetThreadContext failed (error %lu)", GetLastError()));
          }

          InstallCodeSectionGuard();
          return DBG_CONTINUE;
        }
      } else {
        LogF(ltGood, "OEP: %llX", static_cast<unsigned long long>(oep));
      }
    } else {
      Log(ltFatal, "GetThreadContext failed for further OEP check");
    }

    FinishUnpacking(oep);
  }

  if (guardStepping_) {
    // Single-step, then re-protect in OnSinglestep.
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &context)) {
      throw std::runtime_error(
          Format("GetThreadContext failed (error %lu)", GetLastError()));
    }
    context.EFlags |= 0x100;
    SetThreadContext(hThread, &context);
  }

  return DBG_CONTINUE;
}

// --------------------------------------------------------------------------
// OEP restoration
// --------------------------------------------------------------------------

uintptr_t ThemidaDebugger64::TryFindCorrectOEP(uintptr_t hitAddress) {
  uintptr_t result = hitAddress;
  if (majorLinkerVersion_ != 9 && majorLinkerVersion_ != 10 &&
      majorLinkerVersion_ != 11 && majorLinkerVersion_ != 12 &&
      majorLinkerVersion_ != 14) {
    Log(ltFatal,
        "Don't know what to do about OEP for this compiler. Your target "
        "likely won't run.");
    return result;
  }

  // MSVC: Assume HitAddress is at __security_init_cookie.
  // Scan for call __security_init_cookie; jmp __scrt_common_main_seh
  const uint32_t textLen =
      static_cast<uint32_t>(baseOfData_ - peSections_[0].VirtualAddress);
  std::vector<uint8_t> textBuffer(textLen);
  RPM(imageBase_ + peSections_[0].VirtualAddress, textBuffer.data(),
      textBuffer.size());

  const uint32_t scanFor = static_cast<uint32_t>(
      hitAddress - imageBase_ - peSections_[0].VirtualAddress);
  for (uint32_t i = 0; i + 10 <= textLen; ++i) {
    if (textBuffer[i] == 0xE8 && textBuffer[i + 5] == 0xE9 &&
        *reinterpret_cast<const uint32_t*>(textBuffer.data() + i + 1) + i + 5 ==
            scanFor) {
      result = imageBase_ + peSections_[0].VirtualAddress + i;
      LogF(ltGood, "Found suitable real OEP %.9llX",
           static_cast<unsigned long long>(result));
      return result;
    }
  }

  // Got two suspicious reads as last accesses, checking out the VM jmp at OEP?
  if (guardAddrs_.size() >= 2 &&
      guardAddrs_.back() == guardAddrs_[guardAddrs_.size() - 2] + 1) {
    msvcInitCookie_ = hitAddress;
    traceMSVCOEP_ = true;
    return guardAddrs_[guardAddrs_.size() - 2];
  }

  Log(ltFatal, "Real OEP not found. Your target likely won't run.");
  return result;
}

void ThemidaDebugger64::WriteMSVCOEP(uintptr_t crtStartup) {
#pragma pack(push, 1)
  struct {
    uint32_t SubRsp;
    uint8_t Call;
    int32_t CallRel;
    uint32_t AddRsp;
    uint8_t Jmp;
    int32_t JmpRel;
  } instructions{};
#pragma pack(pop)

  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(msvcOEP_),
                   sizeof(instructions), PAGE_EXECUTE_READWRITE, &oldProtect);

  instructions.SubRsp = 0x28EC8348;
  instructions.Call = 0xE8;
  instructions.CallRel =
      static_cast<int32_t>(msvcInitCookie_ - (msvcOEP_ + 4) - 5);
  instructions.AddRsp = 0x28C48348;
  instructions.Jmp = 0xE9;
  instructions.JmpRel =
      static_cast<int32_t>(crtStartup - (msvcOEP_ + 4 + 5 + 4) - 5);

  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(msvcOEP_),
                     &instructions, sizeof(instructions), nullptr);

  LogF(ltGood, "Virtualized MSVC9+ OEP restored: %llX",
       static_cast<unsigned long long>(msvcOEP_));
}

void ThemidaDebugger64::FinishUnpacking(uintptr_t oep) {
  Dumper dumper(process_, executable_, imageBase_, oep);

  // Look for IAT by analyzing code near OEP.
  const uintptr_t iat = DetermineIATAddress(oep, dumper);
  LogF(ltGood, "IAT: %08llX", static_cast<unsigned long long>(iat));

  TraceImports(iat, dumper);

  // Process the IAT into an import directory and dump the binary to disk.
  const std::wstring fileName = MakeUnpackedFileName(executable_);
  dumper.IAT = iat;
  ReportStatus("Rebuilding imports");
  auto pe = dumper.Process();
  ReportStatus("Writing the dump");
  dumper.DumpToFile(fileName, *pe, isDll_);
  LogF(ltGood, "Dump written to: %s", WideToUtf8(fileName).c_str());

  hideThreadEnd_ = true;
  TerminateProcess(process_.hProcess, 0);

  if (fixRelocations_) {
    ReportStatus("Rebuilding relocations");
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

  ReportStatus("Verifying the dump");
  VerifyDump(fileName, isDll_, fixRelocations_);

  MarkSuccess();
  Log(ltGood, "Operation completed successfully.");
}

// --------------------------------------------------------------------------
// Tracing
// --------------------------------------------------------------------------

bool ThemidaDebugger64::TraceIsAtAPI(Tracer& tracer, CONTEXT& context) {
  if (tracer.Counter() > 100 && tracer.Counter() < 5000) {
    uint32_t insnData = 0;
    RPM(context.Rip, &insnData, 4);
    if (insnData == 0x0CB10FF0) {
      // First 4 bytes of "lock cmpxchg [rbx+rbp], ecx"
      traceInVM_ = true;
      Log(ltInfo, "Trace ran into Themida VM, stopping");
      return true;  // Stop
    }
  }

  // Cat & mouse game with fake calls.
  if (context.Rsp < traceStartSP_ &&
      (context.Rip == sleepAPI_ || context.Rip == lstrlenAPI_)) {
    // It'd be better to just execute them, but the tracer currently faults at
    // far jumps for wow64 syscalls.
    LogF(ltInfo, "Skipping anti-trace API at %p",
         reinterpret_cast<void*>(context.Rip));
    uintptr_t returnAddress = 0;
    RPM(context.Rsp, &returnAddress, sizeof(returnAddress));
    context.Rsp += sizeof(returnAddress);
    context.Rip = returnAddress;
  }

  bool result = !tmSectR_.Contains(context.Rip);
  if (result && context.Rsp < traceStartSP_) {
    LogF(ltInfo, "Warning: Might have encountered new fake API at %.8llx",
         static_cast<unsigned long long>(context.Rip));
    result = false;
  }

  if (result) {
    tracedAPI_ = context.Rip;
  }
  return result;
}

}  // namespace magicmida
