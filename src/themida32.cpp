// Magicmida - C++ port
// 32-bit Themida/WinLicense unpacking logic (ported from Themida.pas).
#include "themida32.h"

#include "antidump_fix.h"
#include "patcher.h"
#include "pe_report.h"
#include "reloc_fix.h"
#include "scyllahide.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace magicmida {
namespace {

constexpr uint32_t kStatusSuccess = 0;
constexpr uint32_t kStatusPortNotSet = 0xC0000353;

}  // namespace

ThemidaDebugger::ThemidaDebugger(const std::wstring& executable,
                                 const std::wstring& parameters,
                                 bool create_data, bool use_scylla_hide,
                                 bool fix_relocations)
    : ThemidaCommon(executable, parameters) {
  create_data_sections_ = create_data;
  use_scylla_hide_ = use_scylla_hide;
  fix_relocations_ = fix_relocations;
}

// --------------------------------------------------------------------------
// Debugger hooks
// --------------------------------------------------------------------------

void ThemidaDebugger::OnDebugStart(HANDLE& file_handle, HANDLE thread_handle) {
  if (ExtractFileName(executable_).size() >= 50) {
    // "unpacking a sha256? get rekt!"
    Log(kLogWarning,
        "Long filenames crash some Themida versions (recommend <50)");
  }

  close_handle_api_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CloseHandle"));
  SetBreakpoint(reinterpret_cast<uintptr_t>(close_handle_api_),
                HWBPType::kExecute, false);

  bool scylla_injected = false;
  if (use_scylla_hide_) {
    std::string scylla_error;
    scylla_injected =
        scyllahide::Start(process_.hProcess, process_.dwProcessId,
                          scyllahide::DefaultProfile(), &scylla_error);
    if (scylla_injected) {
      LogF(kLogGood, "Applying embedded ScyllaHide (%s)",
           scyllahide::Version());
    } else {
      LogF(kLogWarning,
           "ScyllaHide injection failed: %s; falling back to internal "
           "anti-anti-debug handling",
           scylla_error.c_str());
    }
  } else {
    Log(kLogWarning,
        "ScyllaHide disabled by the Disable ScyllaHide option; using internal "
        "anti-anti-debug handling");
  }

  if (!scylla_injected) {
    nt_sit_ = reinterpret_cast<void*>(GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "ZwSetInformationThread"));
    SetBreakpoint(reinterpret_cast<uintptr_t>(nt_sit_), HWBPType::kExecute,
                  false);
    ki_fast_system_call_ = reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "KiFastSystemCall"));

    BOOL wow64 = FALSE;
    if (!(IsWow64Process(process_.hProcess, &wow64) && wow64)) {
      SetSoftBP(reinterpret_cast<uintptr_t>(ki_fast_system_call_));
      nt_qip_ = *reinterpret_cast<const uint32_t*>(
          reinterpret_cast<uintptr_t>(GetProcAddress(
              GetModuleHandleW(L"ntdll.dll"), "ZwQueryInformationProcess")) +
          1);
    } else {
      wow64_ = true;
      nt_qip64_ = reinterpret_cast<void*>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "ZwQueryInformationProcess"));
      SetBreakpoint(reinterpret_cast<uintptr_t>(nt_qip64_), HWBPType::kExecute,
                    false);
    }
  }

  virtual_protect_api_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect"));

  sleep_api_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep"));
  lstrlen_api_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "lstrlen"));

  UpdateDR(thread_handle);

  TMInit(file_handle);
}

DWORD ThemidaDebugger::OnAccessViolation(
    HANDLE thread_handle, const EXCEPTION_RECORD& exception_record) {
  if (IsGuardedAddress(exception_record.ExceptionInformation[1])) {
    return ProcessGuardedAccess(thread_handle, exception_record);
  }
  return ThemidaCommon::OnAccessViolation(thread_handle, exception_record);
}

void ThemidaDebugger::OnDLLLoad(const std::wstring& file_name,
                                void* base_address) {
  const std::string lowered = AsciiLowerCase(WideToUtf8(file_name));
  if (lowered.find("\\mscoree.dll") != std::string::npos) {
    Log(kLogInfo, "This might be a .NET program - setting _CorExeMain BP");
    const HMODULE cor_exe_module =
        LoadLibraryW(L"mscoree.dll");  // Load in this process
    if (cor_exe_module == base_address) {
      cor_exe_main_ = reinterpret_cast<void*>(
          GetProcAddress(cor_exe_module, "_CorExeMain"));
      SetSoftBP(reinterpret_cast<uintptr_t>(cor_exe_main_));
    } else {
      Log(kLogFatal, "DLL was loaded at different base than in target!");
    }
  }

  scyllahide::OnDllLoad(file_name);

  ThemidaCommon::OnDLLLoad(file_name, base_address);
}

void ThemidaDebugger::OnHardwareBreakpoint(HANDLE thread_handle,
                                           uintptr_t bp_address,
                                           CONTEXT& context) {
  const uintptr_t eip = context.Eip;

  if (eip == reinterpret_cast<uintptr_t>(close_handle_api_)) {
    uint32_t buf = 0;
    RPM(context.Esp, &buf, 4);

    if (buf < image_boundary_) {
      ResetBreakpoint(eip);
      if (compressed_) {
        SetBreakpoint(image_base_ + 0x1000, HWBPType::kAccess);
      } else {
        SetBreakpoint(reinterpret_cast<uintptr_t>(alloc_mem_api_));
      }
    }
  } else if (eip == reinterpret_cast<uintptr_t>(alloc_mem_api_)) {
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
    LogF(kLogInfo, "AllocMem called from %.8X", buf);

    if ((buf >> 31) != 0) {  // Kernel address, can't be right
      Log(kLogFatal, "AllocMem called from a kernel address, aborting.");
      return;
    }

    if (buf > image_base_ && buf < image_boundary_) {
      ++alloc_mem_counter_;
      if (alloc_mem_counter_ == (compressed_ ? 4 : 5)) {
        ResetBreakpoint(reinterpret_cast<uintptr_t>(alloc_mem_api_));
        if (!themida_v3_) {
          Log(kLogGood, "IAT fixing started.");
          TMIATFix(buf);
        } else {
          InstallCodeSectionGuard(PAGE_NOACCESS);
        }
      }
    }
  } else if (eip == reinterpret_cast<uintptr_t>(cmp_img_base_)) {
    ResetBreakpoint(reinterpret_cast<uintptr_t>(cmp_img_base_));
    TMIATFix3(eip);
  } else if (eip == reinterpret_cast<uintptr_t>(magic_jump_)) {
    ResetBreakpoint(reinterpret_cast<uintptr_t>(magic_jump_));
    TMIATFix4();
  } else if (eip == mj1_) {
    ResetBreakpoint(mj1_);
    TMIATFix5(context.Eax);
  } else if (eip == reinterpret_cast<uintptr_t>(magic_jump_v1_)) {
    ResetBreakpoint(reinterpret_cast<uintptr_t>(magic_jump_v1_));
    TMIATFixThemidaV1(reinterpret_cast<uintptr_t>(magic_jump_v1_));
  } else if (eip == reinterpret_cast<uintptr_t>(alloc_heap_api_)) {
    Log(kLogFatal,
        "Special IAT fix failed, perhaps not needed for this binary");
    ResetBreakpoint(reinterpret_cast<uintptr_t>(alloc_heap_api_));
    SoftBPClear();
    InstallCodeSectionGuard(PAGE_NOACCESS);
  } else if (eip == reinterpret_cast<uintptr_t>(virtual_protect_api_)) {
    // Ensure we break on execution in case it's still on PAGE_READONLY.
    InstallCodeSectionGuard(PAGE_NOACCESS);
  } else if (eip == reinterpret_cast<uintptr_t>(nt_sit_)) {
    uint32_t buf = 0;
    uint32_t info_class = 0;
    if (RPM(context.Esp, &buf, 4) && buf < image_boundary_ &&
        RPM(context.Esp + 8, &info_class, 4) && info_class == 17) {
      Log(kLogGood, "Ignoring NtSetInformationThread(ThreadHideFromDebugger)");
      context.Esp += 5 * 4;  // 4 parameters + ret
      context.Eip = buf;
      context.Eax = kStatusSuccess;
      context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
      if (!SetThreadContext(thread_handle, &context)) {
        Log(kLogFatal, "[NtSetInformationThread] SetContextThread");
      }
    }
  } else if (wow64_ && eip == reinterpret_cast<uintptr_t>(nt_qip64_)) {
    uint32_t buf = 0;
    uint32_t info_class = 0;
    if (RPM(context.Esp, &buf, 4) && RPM(context.Esp + 8, &info_class, 4) &&
        (info_class == 7 || info_class == 30)) {
      if (info_class == 7) {
        Log(kLogGood, "Faking ProcessDebugPort");
      } else {
        Log(kLogGood, "Faking ProcessDebugObjectHandle");
      }
      uint32_t buf2 = 0;
      RPM(context.Esp + 12, &buf2, 4);
      const uint32_t write_buf = 0;  // Debug Port/Debug Object Handle
      WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(buf2),
                         &write_buf, 4, nullptr);
      context.Esp += 6 * 4;  // 5 parameters + ret
      context.Eip = buf;
      if (info_class == 7) {
        context.Eax = kStatusSuccess;
      } else {
        context.Eax = kStatusPortNotSet;
      }
      context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
      if (!SetThreadContext(thread_handle, &context)) {
        Log(kLogFatal, "[KiFastSystemCall] SetContextThread");
      }
    }
  } else if (bp_address == image_base_ + 0x1000) {
    ++base_access_count_;
    LogF(kLogGood, "Accessed text base from %p", reinterpret_cast<void*>(eip));
    if (!base_accessed_) {
      ResetBreakpoint(image_base_ + 0x1000);
      SetBreakpoint(image_base_ + 0x1000, HWBPType::kWrite);
      base_accessed_ = true;
    } else {
      if (TMFinderCheck(&context)) {
        ResetBreakpoint(image_base_ + 0x1000);
        SetBreakpoint(reinterpret_cast<uintptr_t>(alloc_mem_api_),
                      HWBPType::kExecute);
        rep_eip_ = context.Eip;
      } else if (base_access_count_ == 3 && !themida_v2_by_sections_) {
        // Hackish, but seems ok so far.
        themida_v3_ = true;
        Log(kLogInfo, "Assuming Themida v3");
        SelectThemidaSection(context.Eip);
        ResetBreakpoint(image_base_ + 0x1000);
        SetBreakpoint(reinterpret_cast<uintptr_t>(alloc_mem_api_),
                      HWBPType::kExecute);
      }
    }
  } else {
    LogF(kLogInfo, "Accessed %llx from %p",
         static_cast<unsigned long long>(bp_address),
         reinterpret_cast<void*>(eip));
  }
}

DWORD ThemidaDebugger::OnSinglestep(uintptr_t bp_address) {
  if (guard_stepping_) {
    DWORD old_protect = 0;
    VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guard_start_),
                     guard_end_ - guard_start_, guard_protection_,
                     &old_protect);
    guard_stepping_ = false;
    return DBG_CONTINUE;
  }

  return ThemidaCommon::OnSinglestep(bp_address);
}

SoftBPAction ThemidaDebugger::OnSoftwareBreakpoint(HANDLE thread_handle,
                                                   uintptr_t bp_address) {
  CONTEXT context{};
  context.ContextFlags = CONTEXT_FULL;
  GetThreadContext(thread_handle, &context);

  if (!wow64_ &&
      bp_address == reinterpret_cast<uintptr_t>(ki_fast_system_call_)) {
    uint32_t result = 0;
    uint32_t info_class = 0;
    if (context.Eax == nt_qip_ && RPM(context.Esp, &result, 4) &&
        RPM(context.Esp + 12, &info_class, 4) &&
        (info_class == 7 || info_class == 30)) {
      if (info_class == 7) {
        Log(kLogGood, "Faking ProcessDebugPort");
      } else {
        Log(kLogGood, "Faking ProcessDebugObjectHandle");
      }
      uint32_t address = 0;
      RPM(context.Esp + 16, &address, 4);
      const uint32_t write_buf = 0;  // Debug Port
      WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(address),
                         &write_buf, 4, nullptr);
      context.Esp += 4;  // 5 parameters + ret
      context.Eip = result;
      if (info_class == 7) {
        context.Eax = kStatusSuccess;
      } else {
        context.Eax = kStatusPortNotSet;
      }
    } else {
      context.Edx = context.Esp;
      context.Eip = reinterpret_cast<uintptr_t>(ki_fast_system_call_) + 2;
    }

    if (!SetThreadContext(thread_handle, &context)) {
      Log(kLogFatal, "[KiFastSystemCall] SetContextThread");
    }
    return SoftBPAction::kKeepContinueNoStep;
  }

  if (bp_address == reinterpret_cast<uintptr_t>(cor_exe_main_)) {
    DumperDotnet dumper(process_, image_base_);
    dumper.DumpToFile(ExtractFilePath(executable_) +
                      ChangeFileExt(ExtractFileName(executable_),
                                    L"U" + ExtractFileExt(executable_)));
    Log(kLogGood, ".NET process dumped.");
    MarkSuccess();

    hide_thread_end_ = true;
    TerminateProcess(process_.hProcess, 0);
    return SoftBPAction::kClearContinue;
  }

  LogF(kLogInfo, "Software breakpoint at %p",
       reinterpret_cast<void*>(bp_address));

  // Should only be called during IAT patching.
  // eax should hold a module base now.
  if (!new_ver_) {
    const HMODULE m_k32 = GetModuleHandleW(L"kernel32.dll");
    const HMODULE m_u32 = GetModuleHandleW(L"user32.dll");
    const HMODULE m_a32 = GetModuleHandleW(L"advapi32.dll");
    if (context.Eax != reinterpret_cast<uintptr_t>(m_k32) &&
        context.Eax != reinterpret_cast<uintptr_t>(m_u32) &&
        context.Eax != reinterpret_cast<uintptr_t>(m_a32)) {
      // Rare path in certain weird binaries.
      LogF(kLogInfo, "eax: %.8X", context.Eax);
      if (!IsHWBreakpoint(reinterpret_cast<uintptr_t>(alloc_heap_api_))) {
        SetBreakpoint(reinterpret_cast<uintptr_t>(alloc_heap_api_),
                      HWBPType::kExecute);
      }
      // Restore original byte and single step.
      return SoftBPAction::kKeepContinue;
    }

    SoftBPClear();

    const uintptr_t jumper =
        5 + context.Eip +
        *reinterpret_cast<const uint32_t*>(
            tm_sect_ + (context.Eip + 1 - tm_sect_r_.address));

    const uintptr_t result = reinterpret_cast<uintptr_t>(VirtualAllocEx(
        process_.hProcess, nullptr, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    LogF(kLogInfo, "IAT patch location: %08llX",
         static_cast<unsigned long long>(result));

    uint8_t bytes[41]{};
    uint8_t* buf = bytes;
    *reinterpret_cast<uint16_t*>(buf) = 0xF881;  // cmp eax
    *reinterpret_cast<uint32_t*>(buf + 2) =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m_k32));
    *reinterpret_cast<uint32_t*>(buf + 6) = 0xF8811574;
    *reinterpret_cast<uint32_t*>(buf + 10) =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m_a32));
    *reinterpret_cast<uint32_t*>(buf + 14) = 0xF8810D74;
    *reinterpret_cast<uint32_t*>(buf + 18) =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m_u32));
    *reinterpret_cast<uint16_t*>(buf + 22) = 0x0574;
    buf[24] = 0xE9;
    *reinterpret_cast<uint32_t*>(buf + 25) =
        static_cast<uint32_t>(jumper - (result + 24) - 5);
    *reinterpret_cast<uint64_t*>(buf + 29) = 0xE9000002872404C7ull;
    *reinterpret_cast<uint32_t*>(buf + 37) =
        static_cast<uint32_t>(jumper - (result + 36) - 5);
    WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(result), buf,
                       41, nullptr);
    FlushInstructionCache(process_.hProcess, reinterpret_cast<void*>(result),
                          41);

    buf[0] = 0xE9;
    *reinterpret_cast<uint32_t*>(buf + 1) =
        static_cast<uint32_t>(result - context.Eip - 5);
    WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(context.Eip),
                       buf, 5, nullptr);
    FlushInstructionCache(process_.hProcess,
                          reinterpret_cast<void*>(context.Eip), 5);

    Log(kLogGood, "Special IAT patch was successfully written!");
  } else {
    // Teflon time!
    for (EFLRecord& efl : efls_) {
      if (efl.address == 0) {
        efl.address = bp_address;
        if (InstallEFLPatch(bp_address, context, efl)) {
          return SoftBPAction::kClearContinue;
        }
        break;
      }
    }

    SoftBPClear();
    Log(kLogInfo, "Found no base in registers!");
    Log(kLogGood, "Special >> NEW << IAT Patch was written!");
  }

  if (!ancient_ver_) {
    // Not using PAGE_NOACCESS here is a performance optimization for some
    // targets (esp. MC1.14).
    InstallCodeSectionGuard(PAGE_READONLY);
  } else {
    InstallCodeSectionGuard(PAGE_NOACCESS);
  }
  Log(kLogInfo, "Please wait, call site tracing might take a while...");
  return SoftBPAction::kClearContinue;
}

bool ThemidaDebugger::InstallEFLPatch(uintptr_t eip, CONTEXT& context,
                                      EFLRecord& record) {
  std::array<HMODULE, 3> bases = {GetModuleHandleW(L"kernel32.dll"),
                                  GetModuleHandleW(L"user32.dll"),
                                  GetModuleHandleW(L"advapi32.dll")};

  DISASM dis{};
  dis.EIP = reinterpret_cast<uintptr_t>(tm_sect_) + eip - tm_sect_r_.address;
  if (DisasmCheck(dis) == 5) {
    if (*(tm_sect_ + (eip - tm_sect_r_.address)) == 0xE9) {
      throw std::runtime_error("efl oldstyle");
    }
  }

  HMODULE found_base = nullptr;
  uint16_t reg_comp = 0;
  for (HMODULE module : bases) {
    if (context.Eax == reinterpret_cast<uintptr_t>(module)) {
      reg_comp = 0xF881;
    } else if (context.Ecx == reinterpret_cast<uintptr_t>(module)) {
      reg_comp = 0xF981;
    } else if (context.Edx == reinterpret_cast<uintptr_t>(module)) {
      reg_comp = 0xFA81;
    } else if (context.Ebx == reinterpret_cast<uintptr_t>(module)) {
      reg_comp = 0xFB81;
    } else if (context.Ebp == reinterpret_cast<uintptr_t>(module)) {
      reg_comp = 0xFD81;
    } else if (context.Esi == reinterpret_cast<uintptr_t>(module)) {
      reg_comp = 0xFE81;
    } else if (context.Edi == reinterpret_cast<uintptr_t>(module)) {
      reg_comp = 0xFF81;
    } else {
      continue;
    }

    found_base = module;
    break;
  }

  if (found_base == nullptr) {
    return false;
  }

  void* hook_dest = VirtualAllocEx(process_.hProcess, nullptr, 128, MEM_COMMIT,
                                   PAGE_EXECUTE_READWRITE);
  if (hook_dest == nullptr) {
    return false;
  }

  uint8_t bytes[128]{};
  uint8_t* buf = bytes;
  *reinterpret_cast<uint16_t*>(buf) = reg_comp;
  *reinterpret_cast<uint32_t*>(buf + 2) =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bases[0]));
  *reinterpret_cast<uint16_t*>(buf + 6) = 0x2874;
  *reinterpret_cast<uint16_t*>(buf + 8) = reg_comp;
  *reinterpret_cast<uint32_t*>(buf + 10) =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bases[1]));
  *reinterpret_cast<uint16_t*>(buf + 14) = 0x2074;
  *reinterpret_cast<uint16_t*>(buf + 16) = reg_comp;
  *reinterpret_cast<uint32_t*>(buf + 18) =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bases[2]));
  *reinterpret_cast<uint16_t*>(buf + 22) = 0x1874;
  *reinterpret_cast<uint16_t*>(buf + 24) = 0x1DEB;  // jmp to OrigOps
  *reinterpret_cast<uint64_t*>(buf + 0x30) =
      0x90000002462404C7ull;  // mov [esp], 0x246 (EFL patch)
  uint8_t* original_ops = buf + 0x37;

  uint32_t total_size = 0;
  dis.EIP = reinterpret_cast<uintptr_t>(tm_sect_) + eip - tm_sect_r_.address;
  while (total_size < 5) {
    const uintptr_t length = DisasmCheck(dis);
    total_size += static_cast<uint32_t>(length);
    dis.EIP += length;
  }

  // Copy original opcodes.
  std::memcpy(original_ops, tm_sect_ + (eip - tm_sect_r_.address), total_size);
  record.original.assign(original_ops, original_ops + total_size);
  // Calculate jump back.
  original_ops += total_size;
  *original_ops = 0xE9;
  *reinterpret_cast<uint32_t*>(original_ops + 1) =
      static_cast<uint32_t>((eip + total_size) -
                            (static_cast<uintptr_t>(original_ops - buf) +
                             reinterpret_cast<uintptr_t>(hook_dest)) -
                            5);

  // Copy to target.
  WriteProcessMemory(process_.hProcess, hook_dest, buf, 128, nullptr);
  FlushInstructionCache(process_.hProcess, hook_dest, 128);

  // Install hook.
  buf[0] = 0xE9;
  *reinterpret_cast<uint32_t*>(buf + 1) =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hook_dest) - eip - 5);
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
        *reinterpret_cast<uint32_t*>(bytes + 2) =
            static_cast<uint32_t>((reinterpret_cast<uintptr_t>(hook_dest) +
                                   0x37 + (displacement - 3)) -
                                  (eip - 3 - 6) - 6);
        WriteProcessMemory(process_.hProcess,
                           reinterpret_cast<void*>(eip - 3 - 4), bytes + 2, 4,
                           nullptr);
      }
    }
  }

  LogF(kLogGood, "EFL Patch at %08llX", static_cast<unsigned long long>(eip));
  return true;
}

bool ThemidaDebugger::TMFinderCheck(CONTEXT* context) {
  uint16_t rep = 0;
  RPM(context->Eip, &rep, 2);
  if (rep == 0xA4F3) {
    return true;
  }

  const uintptr_t tmp = image_base_ + 0x1000 + base1_ - 4;
  return context->Eax == tmp || context->Ebx == tmp || context->Ecx == tmp ||
         context->Edx == tmp || context->Esi == tmp || context->Edi == tmp;
}

// --------------------------------------------------------------------------
// Themida section handling
// --------------------------------------------------------------------------

void ThemidaDebugger::TMInit(HANDLE& file_handle) {
  if (file_handle == nullptr || file_handle == INVALID_HANDLE_VALUE) {
    file_handle =
        CreateFileW(executable_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE) {
      throw std::runtime_error(Format("CreateFile code %lu", GetLastError()));
    }
  }

  SetFilePointer(file_handle, 0, nullptr, FILE_BEGIN);

  uint8_t buffer[0x1000]{};
  DWORD bytes_read = 0;
  if (!ReadFile(file_handle, buffer, sizeof(buffer), &bytes_read, nullptr)) {
    throw std::runtime_error(
        Format("ReadFile failed! Code: %lu", GetLastError()));
  }
  uint8_t* const buffer_base = buffer;
  const uint64_t nt_offset = static_cast<uint64_t>(
      reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_lfanew);
  if (nt_offset + sizeof(IMAGE_NT_HEADERS) > sizeof(buffer)) {
    throw std::runtime_error("Truncated NT headers");
  }
  uint8_t* const nt_base = buffer + nt_offset;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(nt_base);
  auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
      nt_base + sizeof(IMAGE_NT_HEADERS));
  const uint64_t section_bytes =
      static_cast<uint64_t>(nt->FileHeader.NumberOfSections) *
      sizeof(IMAGE_SECTION_HEADER);
  if (reinterpret_cast<uint64_t>(sections) + section_bytes >
      reinterpret_cast<uint64_t>(buffer) + sizeof(buffer)) {
    throw std::runtime_error("Truncated section table");
  }

  InitPEDetails(nt);

  if (pe_sections_.size() >= 2 &&
      pe_sections_.back().Misc.VirtualSize == 0x1000 &&
      pe_sections_.back().SizeOfRawData == 0x1000 &&
      pe_sections_[pe_sections_.size() - 2].Misc.VirtualSize == 0x1000) {
    themida_v2_by_sections_ = true;
  }

  base_of_data_ = nt->OptionalHeader.BaseOfData;
  compressed_ =
      pe_sections_[0].Misc.VirtualSize != pe_sections_[0].SizeOfRawData;
  base1_ = sections[0].Misc.VirtualSize;

  // PE header antidump.
  if (pe_sections_.size() < 3) {
    throw std::runtime_error("Unexpected PE layout (less than 3 sections)");
  }
  const uintptr_t test = reinterpret_cast<uintptr_t>(&sections[2].Name[0]) -
                         reinterpret_cast<uintptr_t>(buffer_base) + image_base_;
  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(test), 1,
                   PAGE_READWRITE, &old_protect);
  uint32_t value = 'p';
  if (!WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(test),
                          &value, 1, nullptr)) {
    throw std::runtime_error(
        Format("Fixing PE header antidump failed! Code: %lu", GetLastError()));
  }

  if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
    const auto& tls_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_TLS_DIRECTORY32 tls{};
    if (RPM(image_base_ + tls_directory.VirtualAddress, &tls,
            std::min<uint32_t>(tls_directory.Size, sizeof(tls)))) {
      // NOTE: This might be an MSVC-ism, where we assume the TLS callback
      // pointers are located right after the indexes. This allows us to
      // determine the amount of callbacks.
      const intptr_t tls_distance =
          static_cast<intptr_t>(tls.AddressOfCallBacks) -
          static_cast<intptr_t>(tls.AddressOfIndex);
      if (tls_distance > 0 && tls_distance <= 4 * 4) {  // At most 4 TLS entries
        tls_total_ = static_cast<uint32_t>(tls_distance / 4);
        tls_addresses_of_callbacks_ = tls.AddressOfCallBacks;
        LogF(kLogInfo, "Expecting up to %u TLS entries", tls_total_);
      }
    }
  }

  alloc_mem_api_ = reinterpret_cast<void*>(GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "ZwAllocateVirtualMemory"));
  alloc_heap_api_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAllocateHeap"));
}

void ThemidaDebugger::SelectThemidaSection(uintptr_t eip) {
  constexpr char kAncientName[8] = {'T', 'h', 'e', 'm', 'i', 'd', 'a', ' '};

  for (const IMAGE_SECTION_HEADER& section : pe_sections_) {
    if (eip >= section.VirtualAddress + image_base_ &&
        eip < section.VirtualAddress + section.Misc.VirtualSize + image_base_) {
      tm_sect_r_ = MemoryRegion(section.VirtualAddress + image_base_,
                                section.Misc.VirtualSize);
      tm_sect_storage_ = std::make_unique<uint8_t[]>(tm_sect_r_.size);
      tm_sect_ = tm_sect_storage_.get();
      if (!RPM(tm_sect_r_.address, tm_sect_, tm_sect_r_.size)) {
        tm_sect_storage_.reset();
        tm_sect_ = nullptr;
      }
      LogF(kLogInfo, "TMSect: %llX (%zu bytes)",
           static_cast<unsigned long long>(tm_sect_r_.address),
           tm_sect_r_.size);
      if (std::memcmp(section.Name, kAncientName, 8) == 0) {
        ancient_ver_ = true;
        Log(kLogInfo, "Ancient Themida detected.");
      }
      break;
    }
  }

  if (tm_sect_ == nullptr) {
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
  const uint32_t compare_jumps_new =
      FindDynamicTM("74??8B8D????????8B093B8D????????7410");
  if (compare_jumps_new == 0) {
    // Old Themida 1.x versions.
    const uint32_t cmp_eax10000 = FindStaticTM("3D000001000F83");
    if (cmp_eax10000 == 0) {
      Log(kLogFatal, "\"cmp eax, 10000\" not found");
      return;
    }

    LogF(kLogGood, "cmp eax, 10000 at %08X", cmp_eax10000);

    const uint32_t magic_jump_v1 =
        FindDynamicTM("3B8D????????0F84????0000", cmp_eax10000);
    if (magic_jump_v1 == 0) {
      Log(kLogFatal, "First ImageBase compare jump not found");
      return;
    }

    magic_jump_v1_ =
        reinterpret_cast<void*>(static_cast<uintptr_t>(magic_jump_v1));
    SetBreakpoint(magic_jump_v1, HWBPType::kExecute);
  } else {
    LogF(kLogGood, "ImageBase compare jumps found at: %08X", compare_jumps_new);
    cmp_img_base_ =
        reinterpret_cast<void*>(static_cast<uintptr_t>(compare_jumps_new));
    SetBreakpoint(compare_jumps_new, HWBPType::kExecute);
  }
}

void ThemidaDebugger::TMIATFix3(uintptr_t eip) {
  if (eip == 0) {
    throw std::runtime_error("Cannot call TMIATFix3 with EIP=0");
  }

  uint32_t offset = static_cast<uint32_t>(eip - tm_sect_r_.address);
  const uint32_t address = static_cast<uint32_t>(eip) +
                           FindDynamic("4B0F84????0000", tm_sect_ + offset,
                                       tm_sect_r_.size - offset);
  if (address == eip) {
    Log(kLogFatal, "Magic jumps not found");
  } else {
    LogF(kLogGood, "Magic jumps detected at: %08X", address);
    magic_jump_ = reinterpret_cast<void*>(static_cast<uintptr_t>(address));
    SetBreakpoint(address, HWBPType::kExecute);
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
  dis.EIP =
      reinterpret_cast<uintptr_t>(tm_sect_) + (result - tm_sect_r_.address);
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

  LogF(kLogGood, "cmp eax, 50 detected at: %08X",
       static_cast<uint32_t>(result));
  Log(kLogGood, "[LCF-AT] Fixing IAT with the Fast IAT Patch Method.");

  result = FindDynamicTM("3985????????0F84");
  if (result == 0) {
    throw std::runtime_error("Not found");
  }

  const uintptr_t zech = result + 6;
  iat_jumper_ = zech;

  uintptr_t offset = result;
  result = FindStaticTM("2BD90F84", offset);
  if (result == 0) {
    result = FindStaticTM("29CB0F84", offset);
  }
  if (result == 0) {
    throw std::runtime_error("Both patterns not found");
  }

  mj2_ = result;
  const uintptr_t jumper = 6 + mj2_ + 2 +
                           *reinterpret_cast<const uint32_t*>(
                               tm_sect_ + (mj2_ + 4 - tm_sect_r_.address));

  offset = result + 1;
  result = FindStaticTM("2BD90F84", offset);
  if (result == 0) {
    result = FindStaticTM("29CB0F84", offset);
  }
  if (result == 0) {
    throw std::runtime_error("Both patterns not found (2)");
  }

  mj3_ = result;
  const uintptr_t jumper_x2 = 6 + mj3_ + 2 +
                              *reinterpret_cast<const uint32_t*>(
                                  tm_sect_ + (mj3_ + 4 - tm_sect_r_.address));
  if (jumper != jumper_x2) {
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

  while (offset > tm_sect_r_.address &&
         (*reinterpret_cast<const uint16_t*>(
              tm_sect_ + (offset - tm_sect_r_.address)) != 0x840F ||
          6 + offset +
                  *reinterpret_cast<const uint32_t*>(
                      tm_sect_ + (offset + 2 - tm_sect_r_.address)) !=
              jumper)) {
    --offset;
  }

  if (*reinterpret_cast<const uint16_t*>(
          tm_sect_ + (offset - tm_sect_r_.address)) != 0x840F ||
      6 + offset +
              *reinterpret_cast<const uint32_t*>(
                  tm_sect_ + (offset + 2 - tm_sect_r_.address)) !=
          jumper) {
    throw std::runtime_error("Magic jump 1 not found");
  }

  mj1_ = offset;
  LogF(kLogInfo, "MJ1 %08llX", static_cast<unsigned long long>(mj1_));
  LogF(kLogInfo, "MJ2 %08llX", static_cast<unsigned long long>(mj2_));
  LogF(kLogInfo, "MJ3 %08llX", static_cast<unsigned long long>(mj3_));
  LogF(kLogInfo, "MJ4 %08llX", static_cast<unsigned long long>(mj4_));

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
    new_ver_ = false;
  } else {
    new_ver_ = true;
  }

  if (FindDynamicTM(
          "68????????E9??????FF68????????E9??????FF68????????E9??????FF") !=
      0) {
    new_ver_ = false;
  }
  if (FindDynamicTM(
          "68????????68????????E9??????FF68????????68????????E9??????FF") !=
      0) {
    new_ver_ = true;
  }

  if (!new_ver_) {
    Log(kLogInfo, "Older Themida version found.");
  } else {
    Log(kLogInfo, "Newer Themida version found.");
  }

  // NEW_RISC = 1, WL_IS_NEW = 1
  result = FindStaticTM("3BC89CE9");
  if (result == 0) {
    result = tm_sect_r_.address;
    bool valid = GetIATBPAddressNew(result);
    while (result != 0) {
      if (valid) {
        LogF(kLogInfo, "SetSoft: %08llX",
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
      LogF(kLogInfo, "SetSoft : %08llX",
           static_cast<unsigned long long>(result));
      SetSoftBP(result);
      result = FindStaticTM("3BC89CE9", result);
    } while (result != 0);
  }

  // Monitor code section for write accesses (tampering with API call sites,
  // old Themida versions only). The collected addresses are processed in
  // FinishUnpacking/FixupAPICallSites.
  InstallCodeSectionGuard(PAGE_READONLY);  // Performance optimization.

  SetBreakpoint(mj1_, HWBPType::kExecute);
}

void ThemidaDebugger::TMIATFix5(uintptr_t eax) {
  LogF(kLogInfo, "First API in eax: %08llX",
       static_cast<unsigned long long>(eax));

  uint64_t buf = 0xE990;
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(iat_jumper_),
                     &buf, 2, nullptr);
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
  LogF(kLogGood, "IAT Jumper was found & fixed at %llX",
       static_cast<unsigned long long>(iat_jumper_));
}

void ThemidaDebugger::TMIATFixThemidaV1(uintptr_t base_compare1) {
  const uintptr_t base_compare2 =
      FindDynamicTM("3B8D????????0F84????0000", base_compare1 + 12);
  if (base_compare2 == 0) {
    throw std::runtime_error("[Themida 1.x] BaseCompare2 not found");
  }

  const uintptr_t base_compare3 =
      FindDynamicTM("3B8D????????0F84????0000", base_compare2 + 12);
  if (base_compare3 == 0) {
    throw std::runtime_error("[Themida 1.x] BaseCompare3 not found");
  }

  iat_jumper_ = FindDynamicTM("3985????????0F84");
  if (iat_jumper_ == 0) {
    throw std::runtime_error("[Themida 1.x] IAT jumper not found");
  }

  LogF(kLogInfo, "BC1 %llX", static_cast<unsigned long long>(base_compare1));
  LogF(kLogInfo, "BC2 %llX", static_cast<unsigned long long>(base_compare2));
  LogF(kLogInfo, "BC3 %llX", static_cast<unsigned long long>(base_compare3));

  // This is required so Themida doesn't end the process when BaseCompare
  // patches are in place.
  uint64_t buf = 0xE990;
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(iat_jumper_ + 6), &buf, 2,
                     nullptr);
  // These prevent IAT wrapping, which only happens for the three modules
  // kernel32, user32 and advapi32.
  buf = 0x909090909090;
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(base_compare1 + 6), &buf, 6,
                     nullptr);
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(base_compare2 + 6), &buf, 6,
                     nullptr);
  WriteProcessMemory(process_.hProcess,
                     reinterpret_cast<void*>(base_compare3 + 6), &buf, 6,
                     nullptr);

  LogF(kLogGood, "IAT Jumper was found & fixed at %llX",
       static_cast<unsigned long long>(iat_jumper_));

  guard_start_ = image_base_ + pe_sections_[0].VirtualAddress;
  guard_end_ = image_base_ + 0x100000;
  guard_protection_ = PAGE_NOACCESS;
  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guard_start_),
                   guard_end_ - guard_start_, guard_protection_, &old_protect);
}

// --------------------------------------------------------------------------
// Code section guard
// --------------------------------------------------------------------------

void ThemidaDebugger::InstallCodeSectionGuard(uint32_t protection) {
  guard_start_ = image_base_ + pe_sections_[0].VirtualAddress;
  guard_end_ = image_base_ + base_of_data_;
  guard_protection_ = protection;
  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guard_start_),
                   guard_end_ - guard_start_, guard_protection_, &old_protect);

  if (!themida_v3_ &&
      !IsHWBreakpoint(reinterpret_cast<uintptr_t>(virtual_protect_api_))) {
    SetBreakpoint(reinterpret_cast<uintptr_t>(virtual_protect_api_));
  }
}

bool ThemidaDebugger::IsGuardedAddress(uintptr_t address) {
  if (guard_start_ == 0) {
    return false;
  }
  return address >= guard_start_ && address < guard_end_;
}

DWORD ThemidaDebugger::ProcessGuardedAccess(
    HANDLE thread_handle, const EXCEPTION_RECORD& exception_record) {
  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guard_start_),
                   guard_end_ - guard_start_, PAGE_EXECUTE_READWRITE,
                   &old_protect);

  const auto handle_oep = [&]() {
    uintptr_t oep =
        reinterpret_cast<uintptr_t>(exception_record.ExceptionAddress);
    LogF(kLogGood, "OEP: %08llX", static_cast<unsigned long long>(oep));

    RestoreStolenOEPForMSVC6(thread_handle, oep);
    if (is_dll_ && major_linker_version_ == 9) {
      RestoreStolenOEPForMSVC9DLL(thread_handle, oep);
    }
    CheckVirtualizedOEP(oep);

    if (!ancient_ver_) {
      // Check if virtualized and stolen (goes straight into VM without using
      // jmp in .text).
      CONTEXT context{};
      context.ContextFlags = CONTEXT_CONTROL;
      if (GetThreadContext(thread_handle, &context)) {
        uint32_t return_address = 0;
        RPM(context.Esp, &return_address, 4);
        if (tm_sect_r_.Contains(return_address) &&
            !IsTMExceptionHandler(return_address)) {
          LogF(kLogInfo, "OEP return address points into Themida section: %.8X",
               return_address);
          oep = TryFindCorrectOEP(oep);
        }
      } else {
        Log(kLogFatal, "GetThreadContext failed for further OEP check");
      }
    }

    FinishUnpacking(oep);
  };

  if (reinterpret_cast<uintptr_t>(exception_record.ExceptionAddress) >
      guard_end_) {
    guard_addrs_.push_back(exception_record.ExceptionInformation[1]);
    // Single-step, then re-protect in OnHardwareBreakpoint.
    guard_stepping_ = true;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread_handle, &context)) {
      throw std::runtime_error(
          Format("GetThreadContext failed (error %lu)", GetLastError()));
    }
    context.EFlags |= 0x100;
    SetThreadContext(thread_handle, &context);
  } else if (tls_total_ > 0 && tls_counter_ < tls_total_) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(thread_handle, &context)) {
      uint32_t return_address = 0;
      uint32_t args[3]{};
      RPM(context.Esp, &return_address, 4);
      RPM(context.Esp + 4, args, 12);
      if (tm_sect_r_.Contains(return_address) &&
          !IsTMExceptionHandler(return_address) && ((args[0] & 0xFFF) == 0) &&
          args[1] <= 3) {
        ++tls_counter_;
        LogF(kLogGood, "TLS %u: %.8X (%X, %X, %X)", tls_counter_,
             static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
                 exception_record.ExceptionAddress)),
             args[0], args[1], args[2]);
        // Skip execution, we want nothing initialized in the unpacked binary.
        context.Eip = return_address;
        context.Esp += 4 + 3 * 4;
        SetThreadContext(thread_handle, &context);
        InstallCodeSectionGuard(guard_protection_);
      } else {
        LogF(kLogInfo,
             "This doesn't look like TLS (ret %X; args %X, %X, %X), assuming "
             "OEP.",
             return_address, args[0], args[1], args[2]);
        handle_oep();
      }
    } else {
      Log(kLogFatal, "GetThreadContext failed for TLS check");
      handle_oep();
    }
  } else {
    handle_oep();
  }

  return DBG_CONTINUE;
}

// --------------------------------------------------------------------------
// OEP restoration
// --------------------------------------------------------------------------

void ThemidaDebugger::RestoreStolenOEPForMSVC6(HANDLE thread_handle,
                                               uintptr_t& oep) {
  constexpr uint8_t kRestoreData[] = {
      0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0,    0,    0,    0,    0x68, 0,
      0,    0,    0,    0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0x89,
      0x25, 0x00, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x58, 0x53, 0x56, 0x57, 0x89,
      0x65, 0xE8, 0xFF, 0x15, 0,    0,    0,    0,    0x33, 0xD2,
  };
  constexpr size_t kRestoreSize = sizeof(kRestoreData);

  uint8_t check_buffer[3]{};
  RPM(oep, check_buffer, 2);

  // mov dl, ah
  if (check_buffer[0] != 0x8A || check_buffer[1] != 0xD4) {
    return;  // not MSVC6 or not stolen
  }

  Log(kLogInfo, "Stolen MSVC6 OEP detected.");

  RPM(oep - kRestoreSize - 3, check_buffer, 3);
  if (check_buffer[0] != 0xC2 && check_buffer[2] != 0xC3) {
    Log(kLogFatal, "Stolen OEP gap mismatch.");
    return;
  }

  std::array<uint8_t, kRestoreSize> restore_data{};
  std::memcpy(restore_data.data(), kRestoreData, kRestoreSize);
  oep -= kRestoreSize;

  const uintptr_t get_version_address = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetVersion"));

  const uintptr_t iat = image_base_ + base_of_data_;

  std::vector<uintptr_t> iat_data(512);
  RPM(iat, iat_data.data(), iat_data.size() * sizeof(uintptr_t));
  for (size_t i = 0; i < iat_data.size(); ++i) {
    if (iat_data[i] == get_version_address) {
      *reinterpret_cast<uint32_t*>(restore_data.data() + kRestoreSize - 6) =
          static_cast<uint32_t>(iat + i * 4);
      break;
    }
  }

  if (*reinterpret_cast<uint32_t*>(restore_data.data() + kRestoreSize - 6) ==
      0) {
    Log(kLogFatal, "Unable to find GetVersion in IAT.");
    return;
  }

  CONTEXT context{};
  context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
  if (!GetThreadContext(thread_handle, &context)) {
    throw std::runtime_error(
        Format("GetThreadContext failed (error %lu)", GetLastError()));
  }

  if (context.Esp != context.Ebp - 0x74) {
    LogF(kLogFatal, "Stack frame mismatch: esp=%x, ebp=%x", context.Esp,
         context.Ebp);
    return;
  }

  uintptr_t stack_data[2]{};
  RPM(context.Ebp - 3 * sizeof(uintptr_t), stack_data, sizeof(stack_data));

  *reinterpret_cast<uint32_t*>(restore_data.data() + 6) =
      static_cast<uint32_t>(stack_data[1]);
  *reinterpret_cast<uint32_t*>(restore_data.data() + 11) =
      static_cast<uint32_t>(stack_data[0]);

  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(oep),
                     restore_data.data(), kRestoreSize, nullptr);

  LogF(kLogGood, "Correct OEP: %08llX", static_cast<unsigned long long>(oep));
}

void ThemidaDebugger::RestoreStolenOEPForMSVC9DLL(HANDLE /*thread_handle*/,
                                                  uintptr_t& oep) {
  constexpr uint8_t kRestoreData[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83,
                                      0x7D, 0x0C, 0x01, 0x75, 0x05};

  uint8_t check_byte = 0;
  RPM(oep, &check_byte, 1);
  if (check_byte != 0xE8) {
    return;
  }

  RPM(oep - sizeof(kRestoreData), &check_byte, 1);
  if (check_byte != 0xE9) {  // jmp to vm
    return;
  }

  Log(kLogInfo, "Stolen MSVC9 DLL OEP detected.");

  oep -= sizeof(kRestoreData);
  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(oep),
                     kRestoreData, sizeof(kRestoreData), nullptr);

  LogF(kLogGood, "Correct OEP: %08llX", static_cast<unsigned long long>(oep));
}

uintptr_t ThemidaDebugger::TryFindCorrectOEP(uintptr_t oep) {
  uintptr_t result = oep;
  if (major_linker_version_ != 8 && major_linker_version_ != 9 &&
      major_linker_version_ != 10 && major_linker_version_ != 11 &&
      major_linker_version_ != 12 && major_linker_version_ != 14) {
    Log(kLogFatal,
        "Don't know what to do about OEP for this compiler. Your target "
        "likely won't run.");
    return result;
  }

  // MSVC: Assume current (wrong) OEP is at __security_init_cookie.
  // Scan for call __security_init_cookie; jmp __scrt_common_main_seh
  const uint32_t text_len =
      static_cast<uint32_t>(base_of_data_ - pe_sections_[0].VirtualAddress);
  std::vector<uint8_t> text_buffer(text_len);
  {
    RPM(image_base_ + pe_sections_[0].VirtualAddress, text_buffer.data(),
        text_buffer.size());

    const uint32_t scan_for = static_cast<uint32_t>(
        oep - image_base_ - pe_sections_[0].VirtualAddress);
    for (uint32_t i = 0; i + 10 <= text_len; ++i) {
      if (text_buffer[i] == 0xE8 && text_buffer[i + 5] == 0xE9 &&
          *reinterpret_cast<const uint32_t*>(text_buffer.data() + i + 1) + i +
                  5 ==
              scan_for) {
        result = image_base_ + pe_sections_[0].VirtualAddress + i;
        LogF(kLogGood, "Found likely real OEP %.8llX",
             static_cast<unsigned long long>(result));
        return result;
      }
    }

    Log(kLogFatal, "Real OEP not found. Your target likely won't run.");
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
  std::sort(guard_addrs_.begin(), guard_addrs_.end());

  std::vector<uintptr_t> site_set;
  site_set.push_back(guard_addrs_[0]);
  for (size_t i = 1; i < guard_addrs_.size(); ++i) {
    if (guard_addrs_[i] >= site_set.back() + 6) {
      site_set.push_back(guard_addrs_[i]);
    }
  }

  LogF(kLogInfo, "Deduced %zu call sites from %zu accesses", site_set.size(),
       guard_addrs_.size());

  std::vector<uintptr_t> iat_data(kMaxIatSize / sizeof(uintptr_t));
  RPM(iat, iat_data.data(), iat_data.size() * sizeof(uintptr_t));

  std::unordered_map<uintptr_t, uintptr_t> iat_map;
  for (size_t i = 0; i < iat_data.size(); ++i) {
    iat_map[iat_data[i]] = iat + i * 4;
  }

  bool is_jmp = false;
  uintptr_t target = 0;

  for (uintptr_t site_address : site_set) {
    uint8_t site[6]{};
    RPM(site_address, site, 6);
    if (site[0] == 0xE8 || site[0] == 0xE9) {
      target = *reinterpret_cast<const uint32_t*>(site + 1) + site_address + 5;
      is_jmp = site[0] == 0xE9;
    } else if (site[1] == 0xE8 || site[1] == 0xE9) {
      target = *reinterpret_cast<const uint32_t*>(site + 2) + site_address + 6;
      is_jmp = site[1] == 0xE9;
    } else {
      if (site[0] != 0xFF || (site[1] != 0x15 && site[1] != 0x25)) {
        LogF(kLogFatal,
             "Unknown call site at %llX: %02X %02X %02X %02X %02X %02X",
             static_cast<unsigned long long>(site_address), site[0], site[1],
             site[2], site[3], site[4], site[5]);
      }
      continue;
    }

    const auto it = iat_map.find(target);
    if (it == iat_map.end()) {
      LogF(kLogFatal, "Not in IAT: %llX (from %llX)",
           static_cast<unsigned long long>(target),
           static_cast<unsigned long long>(site_address));
      continue;
    }

    // Turn the relative call/jmp into call/jmp dword ptr [iat]
    site[0] = 0xFF;
    site[1] = static_cast<uint8_t>(0x15 + (is_jmp ? 0x10 : 0x00));
    *reinterpret_cast<uint32_t*>(site + 2) = static_cast<uint32_t>(it->second);
    WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(site_address),
                       site, 6, nullptr);
  }
}

void ThemidaDebugger::FinishUnpacking(uintptr_t oep) {
  // Remove EFL jumps from VM code.
  for (EFLRecord& efl : efls_) {
    if (efl.address == 0) {
      break;
    }
    WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(efl.address),
                       efl.original.data(), efl.original.size(), nullptr);
  }

  Dumper dumper(process_, executable_, image_base_, oep);

  // Look for IAT by analyzing code near OEP.
  const uintptr_t iat = DetermineIATAddress(oep, dumper);
  LogF(kLogGood, "IAT: %08llX", static_cast<unsigned long long>(iat));

  // Themida v3: Weak traceable import protection.
  if (themida_v3_) {
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
  if (!guard_addrs_.empty()) {
    FixupAPICallSites(iat);
  }

  if (is_vm_oep_ && themida_v3_) {
    AntiDumpFixer fixer(process_.hProcess, image_base_);
    fixer.RedirectOEP(oep, iat);
  }

  // Process the IAT into an import directory and dump the binary to disk.
  const std::wstring file_name = MakeUnpackedFileName(executable_);
  dumper.iat_ = iat;
  ReportStatus("Rebuilding imports");
  auto pe = dumper.Process();
  ReportStatus("Writing the dump");
  dumper.DumpToFile(file_name, *pe, is_dll_);
  LogF(kLogGood, "Dump written to: %s", WideToUtf8(file_name).c_str());

  hide_thread_end_ = true;
  TerminateProcess(process_.hProcess, 0);

  if (create_data_sections_) {
    ReportStatus("Creating data sections");
    Patcher patcher(file_name);
    if (!patcher.ProcessMkData()) {
      Log(kLogWarning, "Data sections were not created.");
    }
  }

  if (fix_relocations_) {
    ReportStatus("Rebuilding relocations");
    if (is_dll_) {
      try {
        FixDllRelocations(file_name, image_base_);
      } catch (const std::exception& error) {
        LogF(kLogWarning, "Relocation fix failed: %s", error.what());
      }
    } else {
      Log(kLogWarning, "The relocation fix is only applied to DLL targets.");
    }
  }

  ReportStatus("Verifying the dump");
  VerifyDump(file_name, is_dll_, fix_relocations_);

  MarkSuccess();
  Log(kLogGood, "Operation completed successfully.");
}

// --------------------------------------------------------------------------
// Tracing
// --------------------------------------------------------------------------

bool ThemidaDebugger::TraceIsAtAPI(Tracer& tracer, CONTEXT& context) {
  if (tracer.Counter() > 100 && tracer.Counter() < 5000) {
    uint32_t insn_data = 0;
    RPM(context.Eip, &insn_data, 4);
    if (insn_data == 0x4CB10FF0) {
      // First 4 bytes of "lock cmpxchg [ebp+ebx+0], ecx"
      trace_in_vm_ = true;
      Log(kLogInfo, "Trace ran into Themida VM, stopping");
      return true;  // Stop
    }
  }

  // Cat & mouse game with fake calls.
  if (context.Esp < trace_start_sp_ &&
      (context.Eip == sleep_api_ || context.Eip == lstrlen_api_)) {
    // It'd be better to just execute them, but the tracer currently faults at
    // far jumps for wow64 syscalls.
    LogF(kLogInfo, "Skipping anti-trace API at %.8x", context.Eip);
    uint32_t return_address = 0;
    RPM(context.Esp, &return_address, 4);
    context.Esp += 8;
    context.Eip = return_address;
  }

  bool result = !tm_sect_r_.Contains(context.Eip);
  if (result && context.Esp < trace_start_sp_) {
    LogF(kLogInfo, "Warning: Might have encountered new fake API at %.8x",
         context.Eip);
    result = false;
  }

  if (result) {
    traced_api_ = context.Eip;
  }
  return result;
}

}  // namespace magicmida
