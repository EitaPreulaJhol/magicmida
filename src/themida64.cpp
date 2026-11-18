// Magicmida - C++ port
// 64-bit Themida/WinLicense unpacking logic (ported from Themida64.pas).
#include "themida64.h"

#include "pe_report.h"
#include "reloc_fix.h"
#include "scyllahide.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

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
                                     bool create_data, bool use_scylla_hide,
                                     bool fix_relocations)
    : ThemidaCommon(executable, parameters) {
  create_data_sections_ = create_data;  // Currently does nothing.
  use_scylla_hide_ = use_scylla_hide;
  fix_relocations_ = fix_relocations;
  themida_v3_ = true;  // Themida V2 is not supported on x64 atm.
}

bool ThemidaDebugger64::InImageBounds(uintptr_t address) const {
  return address >= image_base_ && address < image_boundary_;
}

// --------------------------------------------------------------------------
// Debugger hooks
// --------------------------------------------------------------------------

void ThemidaDebugger64::SelectThemidaSection(uintptr_t address) {
  for (const IMAGE_SECTION_HEADER& section : pe_sections_) {
    if (address >= section.VirtualAddress + image_base_ &&
        address <
            section.VirtualAddress + section.Misc.VirtualSize + image_base_) {
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
      break;
    }
  }

  if (tm_sect_ == nullptr) {
    throw std::runtime_error(Format("Unable to find section for %llX",
                                    static_cast<unsigned long long>(address)));
  }
}

void ThemidaDebugger64::OnDebugStart(HANDLE& file_handle,
                                     HANDLE thread_handle) {
  if (use_scylla_hide_) {
    std::string scylla_error;
    if (!scyllahide::Start(process_.hProcess, process_.dwProcessId,
                           scyllahide::DefaultProfile(), &scylla_error)) {
      throw std::runtime_error("ScyllaHide injection failed: " + scylla_error);
    }
    LogF(kLogGood, "Applying embedded ScyllaHide (%s)", scyllahide::Version());
  } else {
    Log(kLogWarning,
        "ScyllaHide disabled by the Disable ScyllaHide option; Themida64 may "
        "detect the debugger");
  }

  virtual_alloc_api_ = reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualAlloc"));

  sleep_api_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep"));
  lstrlen_api_ = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "lstrlen"));

  TMInit(file_handle);
}

DWORD ThemidaDebugger64::OnAccessViolation(
    HANDLE thread_handle, const EXCEPTION_RECORD& exception_record) {
  if (IsGuardedAddress(exception_record.ExceptionInformation[1])) {
    return ProcessGuardedAccess(thread_handle, exception_record);
  }
  return ThemidaCommon::OnAccessViolation(thread_handle, exception_record);
}

void ThemidaDebugger64::OnDLLLoad(const std::wstring& file_name,
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

void ThemidaDebugger64::OnHardwareBreakpoint(HANDLE /*thread_handle*/,
                                             uintptr_t bp_address,
                                             CONTEXT& context) {
  const uintptr_t eip = context.Rip;

  if (eip == reinterpret_cast<uintptr_t>(close_handle_api_)) {
    uintptr_t buf = 0;
    RPM(context.Rsp, &buf, 8);

    LogF(kLogInfo, "CloseHandle called from from %p",
         reinterpret_cast<void*>(buf));

    if (InImageBounds(buf)) {
      ResetBreakpoint(eip);
      SetBreakpoint(image_base_ + 0x1000, HWBPType::kWrite);
    }
  } else if (eip == reinterpret_cast<uintptr_t>(virtual_alloc_api_)) {
    uintptr_t buf = 0;
    RPM(context.Rsp, &buf, 8);
    LogF(kLogInfo, "AllocMem called from %llX",
         static_cast<unsigned long long>(buf));

    if (InImageBounds(buf)) {
      ResetBreakpoint(reinterpret_cast<uintptr_t>(virtual_alloc_api_));
      InstallCodeSectionGuard();
    }
  } else if (bp_address == image_base_ + 0x1000) {
    LogF(kLogGood, "Wrote to .text base from %llX",
         static_cast<unsigned long long>(eip));

    if (tm_sect_r_.address == 0) {
      SelectThemidaSection(eip);
    }

    ResetBreakpoint(image_base_ + 0x1000);
    SetBreakpoint(reinterpret_cast<uintptr_t>(virtual_alloc_api_),
                  HWBPType::kExecute);
  } else {
    LogF(kLogInfo, "Accessed %llx from %p",
         static_cast<unsigned long long>(bp_address),
         reinterpret_cast<void*>(eip));
  }
}

DWORD ThemidaDebugger64::OnSinglestep(uintptr_t bp_address) {
  if (guard_stepping_) {
    DWORD old_protect = 0;
    if (!VirtualProtectEx(
            process_.hProcess, reinterpret_cast<void*>(guard_start_),
            guard_end_ - guard_start_, PAGE_NOACCESS, &old_protect)) {
      throw std::runtime_error(
          Format("VirtualProtectEx failed (error %lu)", GetLastError()));
    }
    guard_stepping_ = false;
    return DBG_CONTINUE;
  }

  return ThemidaCommon::OnSinglestep(bp_address);
}

SoftBPAction ThemidaDebugger64::OnSoftwareBreakpoint(HANDLE /*thread_handle*/,
                                                     uintptr_t bp_address) {
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

  throw std::runtime_error(
      Format("Unexpected SoftBP at %p", reinterpret_cast<void*>(bp_address)));
}

void ThemidaDebugger64::DumpContext(DWORD thread_id) {
  HANDLE thread_handle = GetThread(thread_id);
  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  if (!GetThreadContext(thread_handle, &context)) {
    Log(kLogFatal, "DumpContext: GetThreadContext failed");
    return;
  }

  LogF(kLogInfo, "rax: %llX rbx: %llX rcx: %llX rdx: %llX rsi: %llX rdi: %llX",
       static_cast<unsigned long long>(context.Rax),
       static_cast<unsigned long long>(context.Rbx),
       static_cast<unsigned long long>(context.Rcx),
       static_cast<unsigned long long>(context.Rdx),
       static_cast<unsigned long long>(context.Rsi),
       static_cast<unsigned long long>(context.Rdi));
  LogF(kLogInfo,
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
  LogF(kLogInfo, "rip: %llX rbp: %llX rsp: %llX eflags: %lX",
       static_cast<unsigned long long>(context.Rip),
       static_cast<unsigned long long>(context.Rbp),
       static_cast<unsigned long long>(context.Rsp),
       static_cast<unsigned long>(context.EFlags));
}

// --------------------------------------------------------------------------
// Themida section handling
// --------------------------------------------------------------------------

void ThemidaDebugger64::TMInit(HANDLE& file_handle) {
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

  if (pe_sections_.size() < 3) {
    throw std::runtime_error("Unexpected PE layout (less than 3 sections)");
  }

  base_of_data_ = sections[0].VirtualAddress + nt->OptionalHeader.SizeOfCode;

  // PE header antidump.
  if (sections[2].Name[0] == 'i') {
    const uintptr_t test = reinterpret_cast<uintptr_t>(&sections[2].Name[0]) -
                           reinterpret_cast<uintptr_t>(buffer) + image_base_;
    DWORD old_protect = 0;
    VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(test), 1,
                     PAGE_READWRITE, &old_protect);
    uint32_t value = 'p';
    if (!WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(test),
                            &value, 1, nullptr)) {
      throw std::runtime_error(Format(
          "Fixing PE header antidump failed! Code: %lu", GetLastError()));
    }
  }

  if (SectionNameTrimmed(sections[0]) == ".text") {
    // Code not encrypted/compressed.
    Log(kLogGood,
        "Text section not encrypted/compressed, installing page guard");
    InstallCodeSectionGuard();
  } else {
    close_handle_api_ = reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CloseHandle"));
    SetBreakpoint(reinterpret_cast<uintptr_t>(close_handle_api_),
                  HWBPType::kExecute);
  }

  if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
    const auto& tls_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_TLS_DIRECTORY64 tls{};
    if (RPM(image_base_ + tls_directory.VirtualAddress, &tls,
            std::min<uint32_t>(tls_directory.Size, sizeof(tls)))) {
      // NOTE: This is an MSVC-ism, where we assume the TLS callback pointers
      // are located right before the TLS directory. This allows us to
      // determine the amount of callbacks.
      const intptr_t tls_distance =
          static_cast<intptr_t>(image_base_ + tls_directory.VirtualAddress) -
          static_cast<intptr_t>(tls.AddressOfCallBacks);
      if (tls_distance > 0 &&
          tls_distance <= static_cast<intptr_t>(sizeof(uintptr_t) * (4 + 1))) {
        // Assume at most 4 TLS entries + zero terminator.
        tls_total_ =
            static_cast<uint32_t>(tls_distance / sizeof(uintptr_t)) - 1;
        LogF(kLogInfo, "[MSVC] Expecting %u TLS entries", tls_total_);
      }
    }
  }
}

// --------------------------------------------------------------------------
// Code section guard
// --------------------------------------------------------------------------

void ThemidaDebugger64::InstallCodeSectionGuard() {
  guard_start_ = image_base_ + pe_sections_[0].VirtualAddress;
  guard_end_ = image_base_ + base_of_data_;
  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guard_start_),
                   guard_end_ - guard_start_, PAGE_NOACCESS, &old_protect);
}

bool ThemidaDebugger64::IsGuardedAddress(uintptr_t address) {
  if (guard_start_ == 0) {
    return false;
  }
  return address >= guard_start_ && address < guard_end_;
}

DWORD ThemidaDebugger64::ProcessGuardedAccess(
    HANDLE thread_handle, const EXCEPTION_RECORD& exception_record) {
  LogF(kLogInfo, "[Guard] %s %llX",
       AccessViolationFlagToStr(
           static_cast<uint8_t>(exception_record.ExceptionInformation[0]))
           .c_str(),
       static_cast<unsigned long long>(
           exception_record.ExceptionInformation[1]));

  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guard_start_),
                   guard_end_ - guard_start_, PAGE_EXECUTE_READWRITE,
                   &old_protect);

  const uintptr_t exception_address =
      reinterpret_cast<uintptr_t>(exception_record.ExceptionAddress);

  if (tm_guard_) {
    // We've hit the Themida section after executing a TLS entrypoint.
    tm_guard_ = false;
    InstallCodeSectionGuard();
  } else if (!InImageBounds(exception_address)) {
    // Random library code reading our text base...
    guard_stepping_ = true;
  } else if (exception_address > guard_end_) {
    // Themida access.
    if (tm_sect_r_.address == 0) {
      SelectThemidaSection(exception_address);
    }

    guard_addrs_.push_back(exception_record.ExceptionInformation[1]);
    guard_stepping_ = true;
  } else if (exception_record.ExceptionInformation[0] == 8 && tls_total_ > 0 &&
             tls_counter_ < tls_total_) {
    ++tls_counter_;
    LogF(kLogGood, "TLS %u: %.9llX", tls_counter_,
         static_cast<unsigned long long>(exception_address));
    guard_start_ = tm_sect_r_.address;
    guard_end_ = image_boundary_;
    tm_guard_ = true;
    // Allow R/W, disallow execute. Some weird binaries read a byte at the PE's
    // AddressOfEntryPoint in TLS...
    VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(guard_start_),
                     guard_end_ - guard_start_, PAGE_READWRITE, &old_protect);
  } else if (trace_msvc_oep_) {
    // We're at mainCrtStartup.
    WriteMSVCOEP(exception_address);
    FinishUnpacking(msvc_oep_);
  } else {
    uintptr_t oep = exception_address;

    // Check if virtualized (but goes to .text first for jmp).
    CheckVirtualizedOEP(oep);

    // Check if virtualized and stolen (goes straight into VM without using jmp
    // in .text).
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(thread_handle, &context)) {
      uintptr_t return_address = 0;
      RPM(context.Rsp, &return_address, 8);
      if (tm_sect_r_.Contains(return_address)) {
        LogF(kLogInfo, "Return address points into Themida section: %.9llX",
             static_cast<unsigned long long>(return_address));
        oep = TryFindCorrectOEP(oep);

        if (trace_msvc_oep_) {
          msvc_oep_ = oep;

          // Skip and wait for next .text hit.
          context.Rip = return_address;
          context.Rsp += 8;
          if (!SetThreadContext(thread_handle, &context)) {
            throw std::runtime_error(
                Format("SetThreadContext failed (error %lu)", GetLastError()));
          }

          InstallCodeSectionGuard();
          return DBG_CONTINUE;
        }
      } else {
        LogF(kLogGood, "OEP: %llX", static_cast<unsigned long long>(oep));
      }
    } else {
      Log(kLogFatal, "GetThreadContext failed for further OEP check");
    }

    FinishUnpacking(oep);
  }

  if (guard_stepping_) {
    // Single-step, then re-protect in OnSinglestep.
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread_handle, &context)) {
      throw std::runtime_error(
          Format("GetThreadContext failed (error %lu)", GetLastError()));
    }
    context.EFlags |= 0x100;
    SetThreadContext(thread_handle, &context);
  }

  return DBG_CONTINUE;
}

// --------------------------------------------------------------------------
// OEP restoration
// --------------------------------------------------------------------------

uintptr_t ThemidaDebugger64::TryFindCorrectOEP(uintptr_t hit_address) {
  uintptr_t result = hit_address;
  if (major_linker_version_ != 8 && major_linker_version_ != 9 &&
      major_linker_version_ != 10 && major_linker_version_ != 11 &&
      major_linker_version_ != 12 && major_linker_version_ != 14) {
    Log(kLogFatal,
        "Don't know what to do about OEP for this compiler. Your target "
        "likely won't run.");
    return result;
  }

  // MSVC: Assume HitAddress is at __security_init_cookie.
  // Scan for call __security_init_cookie; jmp __scrt_common_main_seh
  const uint32_t text_len =
      static_cast<uint32_t>(base_of_data_ - pe_sections_[0].VirtualAddress);
  std::vector<uint8_t> text_buffer(text_len);
  RPM(image_base_ + pe_sections_[0].VirtualAddress, text_buffer.data(),
      text_buffer.size());

  const uint32_t scan_for = static_cast<uint32_t>(
      hit_address - image_base_ - pe_sections_[0].VirtualAddress);
  for (uint32_t i = 0; i + 10 <= text_len; ++i) {
    if (text_buffer[i] == 0xE8 && text_buffer[i + 5] == 0xE9 &&
        *reinterpret_cast<const uint32_t*>(text_buffer.data() + i + 1) + i +
                5 ==
            scan_for) {
      result = image_base_ + pe_sections_[0].VirtualAddress + i;
      LogF(kLogGood, "Found suitable real OEP %.9llX",
           static_cast<unsigned long long>(result));
      return result;
    }
  }

  // Got two suspicious reads as last accesses, checking out the VM jmp at OEP?
  if (guard_addrs_.size() >= 2 &&
      guard_addrs_.back() == guard_addrs_[guard_addrs_.size() - 2] + 1) {
    msvc_init_cookie_ = hit_address;
    trace_msvc_oep_ = true;
    return guard_addrs_[guard_addrs_.size() - 2];
  }

  Log(kLogFatal, "Real OEP not found. Your target likely won't run.");
  return result;
}

void ThemidaDebugger64::WriteMSVCOEP(uintptr_t crt_startup) {
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

  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(msvc_oep_),
                   sizeof(instructions), PAGE_EXECUTE_READWRITE, &old_protect);

  instructions.SubRsp = 0x28EC8348;
  instructions.Call = 0xE8;
  instructions.CallRel =
      static_cast<int32_t>(msvc_init_cookie_ - (msvc_oep_ + 4) - 5);
  instructions.AddRsp = 0x28C48348;
  instructions.Jmp = 0xE9;
  instructions.JmpRel =
      static_cast<int32_t>(crt_startup - (msvc_oep_ + 4 + 5 + 4) - 5);

  WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(msvc_oep_),
                     &instructions, sizeof(instructions), nullptr);

  LogF(kLogGood, "Virtualized MSVC9+ OEP restored: %llX",
       static_cast<unsigned long long>(msvc_oep_));
}

void ThemidaDebugger64::FinishUnpacking(uintptr_t oep) {
  Dumper dumper(process_, executable_, image_base_, oep);

  // Look for IAT by analyzing code near OEP.
  const uintptr_t iat = DetermineIATAddress(oep, dumper);
  LogF(kLogGood, "IAT: %08llX", static_cast<unsigned long long>(iat));

  TraceImports(iat, dumper);

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

bool ThemidaDebugger64::TraceIsAtAPI(Tracer& tracer, CONTEXT& context) {
  if (tracer.Counter() > 100 && tracer.Counter() < 5000) {
    uint32_t insn_data = 0;
    RPM(context.Rip, &insn_data, 4);
    if (insn_data == 0x0CB10FF0) {
      // First 4 bytes of "lock cmpxchg [rbx+rbp], ecx"
      trace_in_vm_ = true;
      Log(kLogInfo, "Trace ran into Themida VM, stopping");
      return true;  // Stop
    }
  }

  // Cat & mouse game with fake calls.
  if (context.Rsp < trace_start_sp_ &&
      (context.Rip == sleep_api_ || context.Rip == lstrlen_api_)) {
    // It'd be better to just execute them, but the tracer currently faults at
    // far jumps for wow64 syscalls.
    LogF(kLogInfo, "Skipping anti-trace API at %p",
         reinterpret_cast<void*>(context.Rip));
    uintptr_t return_address = 0;
    RPM(context.Rsp, &return_address, sizeof(return_address));
    context.Rsp += sizeof(return_address);
    context.Rip = return_address;
  }

  bool result = !tm_sect_r_.Contains(context.Rip);
  if (result && context.Rsp < trace_start_sp_) {
    LogF(kLogInfo, "Warning: Might have encountered new fake API at %.8llx",
         static_cast<unsigned long long>(context.Rip));
    result = false;
  }

  if (result) {
    traced_api_ = context.Rip;
  }
  return result;
}

}  // namespace magicmida
