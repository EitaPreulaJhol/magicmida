// Magicmida - C++ port
// Debugger primitives: process creation, debug loop, HW/SW breakpoints.
// SPDX-License-Identifier: GPL-3.0-only
#include "debugger_core.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

#include "dumper.h"
#include "pe_info.h"
#include "scyllahide.h"
#include "stream.h"

namespace magicmida {

// Declared here rather than in common.h: the vendored ntdll.h used by
// scyllahide.cpp already declares this symbol, and the two prototypes clash.
extern "C" NtStatus __stdcall NtQueryInformationProcess(
    HANDLE process_handle, DWORD process_information_class,
    PVOID process_information, DWORD process_information_length,
    PULONG return_length);

namespace {

constexpr uintptr_t kOffsetImageBase = sizeof(void*) == 4 ? 8 : 16;
constexpr uintptr_t kOffsetShimData = sizeof(void*) == 4 ? 0x1E8 : 0x2D8;

std::wstring TrimRight(std::wstring value) {
  while (!value.empty() && (value.back() == L' ' || value.back() == L'\t' ||
                            value.back() == L'\r' || value.back() == L'\n')) {
    value.pop_back();
  }
  return value;
}

}  // namespace

// --------------------------------------------------------------------------
// Construction
// --------------------------------------------------------------------------

DebuggerCore::DebuggerCore(const std::wstring& executable,
                           const std::wstring& parameters)
    : executable_(executable), parameters_(parameters) {}

DebuggerCore::DebuggerCore(DWORD attach_pid) : attach_pid_(attach_pid) {}

// --------------------------------------------------------------------------
// Debug loop
// --------------------------------------------------------------------------

void DebuggerCore::Run() {
  try {
    if (!PeExecute()) {
      throw std::runtime_error(
          Format("CreateProcess failed (error %lu)", GetLastError()));
    }
  } catch (const std::exception& error) {
    LogF(kLogFatal, "Creating the process failed: %s", error.what());
    if (is_dll_) {
      DeleteDllCopy();
    }
    CloseProcessHandles();
    return;
  }

  bool process_exited = false;
  bool stop = false;
  try {
    DWORD status = DBG_CONTINUE;
    for (;;) {
      DEBUG_EVENT debug_event{};
      if (!WaitForDebugEvent(&debug_event, 200)) {
        const DWORD error = GetLastError();
        if (error == ERROR_SEM_TIMEOUT) {
          if (IsCancellationRequested()) {
            Log(kLogWarning, "Cancellation requested; stopping.");
            stop = true;
            break;
          }
          continue;
        }
        LogF(kLogFatal, "OS Error: WaitForDebugEvent failed (error %lu)",
             error);
        break;
      }

      if (IsCancellationRequested()) {
        Log(kLogWarning, "Cancellation requested; stopping.");
        stop = true;
        break;
      }

      current_thread_id_ = debug_event.dwThreadId;

      switch (debug_event.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
          status = DBG_EXCEPTION_NOT_HANDLED;
          switch (MM_EVENT_FIELD(debug_event, Exception)
                      .ExceptionRecord.ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION:
              status = OnAccessViolation(
                  GetThread(debug_event.dwThreadId),
                  MM_EVENT_FIELD(debug_event, Exception).ExceptionRecord);
              break;

            case EXCEPTION_BREAKPOINT:
              if (soft_bps_.find(reinterpret_cast<uintptr_t>(
                      MM_EVENT_FIELD(debug_event, Exception)
                          .ExceptionRecord.ExceptionAddress)) !=
                  soft_bps_.end()) {
                status = OnSoftwareBreakpointEvent(debug_event);
              } else {
                OnUnsolicitedSoftwareBreakpoint(
                    GetThread(debug_event.dwThreadId),
                    reinterpret_cast<uintptr_t>(
                        MM_EVENT_FIELD(debug_event, Exception)
                            .ExceptionRecord.ExceptionAddress));
              }
              break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
              // First chance: pass this on to the system.
              break;

            case EXCEPTION_SINGLE_STEP:
              status = OnHardwareBreakpointEvent(debug_event);
              break;

            case DBG_CONTROL_C:
              break;

            default:
              if (MM_EVENT_FIELD(debug_event, Exception).dwFirstChance == 0) {
                LogF(kLogFatal, "dwFirstChance = 0");
                stop = true;
                break;
              }
              LogF(kLogInfo, "Code 0x%.8X at 0x%p",
                   MM_EVENT_FIELD(debug_event, Exception)
                       .ExceptionRecord.ExceptionCode,
                   MM_EVENT_FIELD(debug_event, Exception)
                       .ExceptionRecord.ExceptionAddress);
              status = DBG_EXCEPTION_NOT_HANDLED;
              break;
          }
          break;
        }

        case CREATE_THREAD_DEBUG_EVENT:
          status = OnCreateThreadDebugEvent(debug_event);
          break;

        case CREATE_PROCESS_DEBUG_EVENT:
          status = OnCreateProcessDebugEvent(debug_event);
          break;

        case EXIT_THREAD_DEBUG_EVENT:
          status = OnExitThreadDebugEvent(debug_event);
          break;

        case EXIT_PROCESS_DEBUG_EVENT:
          status = OnExitProcessDebugEvent(debug_event);
          ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId,
                             status);
          process_exited = true;
          break;

        case LOAD_DLL_DEBUG_EVENT:
          status = OnLoadDllDebugEvent(debug_event);
          break;

        case UNLOAD_DLL_DEBUG_EVENT:
          status = OnUnloadDllDebugEvent(debug_event);
          break;

        case OUTPUT_DEBUG_STRING_EVENT:
          status = OnOutputDebugStringEvent(debug_event);
          break;

        case RIP_EVENT:
          status = OnRipEvent(debug_event);
          break;

        default:
          break;
      }

      if (process_exited || stop) {
        break;
      }

      ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId,
                         status);
    }
  } catch (const std::exception& error) {
    LogF(kLogFatal, "Critical error in debug loop: %s", error.what());
  }

  if (!process_exited) {
    TerminateDebuggee();
  }

  if (is_dll_) {
    if (process_.hProcess != nullptr) {
      WaitForSingleObject(process_.hProcess, 5000);
    }
    DeleteDllCopy();
  }

  CloseProcessHandles();
}

void DebuggerCore::TerminateDebuggee() {
  if (process_.hProcess == nullptr) {
    return;
  }

  DWORD exit_code = 0;
  if (GetExitCodeProcess(process_.hProcess, &exit_code) &&
      exit_code == STILL_ACTIVE) {
    Log(kLogWarning, "Terminating the target process.");
    TerminateProcess(process_.hProcess, 1);
  }
}

void DebuggerCore::DeleteDllCopy() {
  if (dll_executable_.empty()) {
    return;
  }

  // The copy may have been marked read-only or be briefly held by the
  // process/AV after termination; retry before giving up.
  SetFileAttributesW(dll_executable_.c_str(), FILE_ATTRIBUTE_NORMAL);
  for (int attempt = 0; attempt < 10; ++attempt) {
    if (DeleteFileW(dll_executable_.c_str())) {
      LogF(kLogInfo, "Removed temporary DLL copy: %s",
           WideToUtf8(dll_executable_).c_str());
      return;
    }
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND) {
      return;
    }
    if (attempt == 9) {
      LogF(kLogWarning,
           "Could not remove temporary DLL copy %s (error %lu); it will be "
           "deleted on the next DLL unpack.",
           WideToUtf8(dll_executable_).c_str(), error);
      return;
    }
    Sleep(100);
  }
}

void DebuggerCore::CloseProcessHandles() {
  // Drop the ScyllaHide session first: it owns a duplicate of the process
  // handle.
  scyllahide::Stop();

  for (auto& entry : threads_) {
    if (entry.second != nullptr && entry.second != INVALID_HANDLE_VALUE) {
      CloseHandle(entry.second);
    }
  }
  threads_.clear();

  if (process_.hThread != nullptr) {
    CloseHandle(process_.hThread);
    process_.hThread = nullptr;
  }
  if (process_.hProcess != nullptr) {
    CloseHandle(process_.hProcess);
    process_.hProcess = nullptr;
  }
}

void DebuggerCore::Detach() {
  for (const auto& entry : threads_) {
    SuspendThread(entry.second);
  }

  const BOOL detached = DebugActiveProcessStop(process_.dwProcessId);

  // Undo the suspend performed above; otherwise the detached target would
  // stay frozen forever.
  for (const auto& entry : threads_) {
    ResumeThread(entry.second);
  }

  if (detached) {
    Log(kLogInfo, "Detached.");
  } else {
    Log(kLogFatal, "Detaching failed.");
  }
}

HANDLE DebuggerCore::GetThread(DWORD thread_id) {
  const auto it = threads_.find(thread_id);
  if (it == threads_.end()) {
    throw std::runtime_error(Format("Thread %lu not found", thread_id));
  }
  return it->second;
}

// --------------------------------------------------------------------------
// Debug events
// --------------------------------------------------------------------------

DWORD DebuggerCore::OnCreateThreadDebugEvent(DEBUG_EVENT& debug_event) {
  LogF(kLogInfo, "[%.4d] Thread started (%p).", debug_event.dwThreadId,
       MM_EVENT_FIELD(debug_event, CreateThread).lpStartAddress);

  const auto it = threads_.find(debug_event.dwThreadId);
  if (it != threads_.end()) {
    CloseHandle(it->second);
  }
  threads_[debug_event.dwThreadId] =
      MM_EVENT_FIELD(debug_event, CreateThread).hThread;
  UpdateDr(MM_EVENT_FIELD(debug_event, CreateThread).hThread);

  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnAccessViolation(
    HANDLE /*thread_handle*/, const EXCEPTION_RECORD& exception_record) {
  LogF(kLogInfo, "[%lu] Access violation at 0x%p: %s of 0x%p",
       current_thread_id_, exception_record.ExceptionAddress,
       AccessViolationFlagToStr(
           static_cast<uint8_t>(exception_record.ExceptionInformation[0]))
           .c_str(),
       reinterpret_cast<void*>(exception_record.ExceptionInformation[1]));
  return DBG_EXCEPTION_NOT_HANDLED;
}

DWORD DebuggerCore::OnCreateProcessDebugEvent(DEBUG_EVENT& debug_event) {
  LogF(kLogInfo, "Running on Windows build %u", GetWindowsBuildNumber());
  LogF(kLogInfo, "Debug session launched (PID: %lu, TID: %lu)",
       debug_event.dwProcessId, debug_event.dwThreadId);

  const HANDLE event_process =
      MM_EVENT_FIELD(debug_event, CreateProcessInfo).hProcess;
  if (process_.hProcess != nullptr && process_.hProcess != event_process) {
    // CreateProcessW returned a handle to the same process; the debug event
    // handle replaces it for the rest of the session.
    CloseHandle(process_.hProcess);
  }
  process_.hProcess = event_process;
  process_.dwProcessId = debug_event.dwProcessId;

  ProcessBasicInformation pbi{};
  NtQueryInformationProcess(process_.hProcess, 0, &pbi, sizeof(pbi), nullptr);
  LogF(kLogInfo, "PEB: %p", pbi.peb_base_address);

  uint8_t byte_value = 0;
  if (ReadProcessMemory(process_.hProcess,
                        static_cast<uint8_t*>(pbi.peb_base_address) + 2,
                        &byte_value, 1, nullptr)) {
    if (byte_value == 1) {
      Log(kLogGood, "Patching PEB.BeingDebugged");
      byte_value = 0;
      WriteProcessMemory(process_.hProcess,
                         static_cast<uint8_t*>(pbi.peb_base_address) + 2,
                         &byte_value, 1, nullptr);
    }
  } else {
    Log(kLogFatal, "Reading PEB failed");
  }

  if (ReadProcessMemory(
          process_.hProcess,
          static_cast<uint8_t*>(pbi.peb_base_address) + kOffsetImageBase,
          &image_base_, sizeof(image_base_), nullptr)) {
    LogF(kLogInfo, "Process Image Base: %p",
         reinterpret_cast<void*>(image_base_));
  } else {
    throw std::runtime_error("Reading process image base failed");
  }

  uintptr_t shim_data = 0;
  if (ReadProcessMemory(
          process_.hProcess,
          static_cast<uint8_t*>(pbi.peb_base_address) + kOffsetShimData,
          &shim_data, sizeof(shim_data), nullptr) &&
      shim_data != 0) {
    shim_data = 0;
    if (WriteProcessMemory(
            process_.hProcess,
            static_cast<uint8_t*>(pbi.peb_base_address) + kOffsetShimData,
            &shim_data, sizeof(shim_data), nullptr)) {
      Log(kLogInfo, "Cleared PEB.pShimData to prevent apphelp hooks");
    }
  }

  threads_[debug_event.dwThreadId] =
      MM_EVENT_FIELD(debug_event, CreateProcessInfo).hThread;

  OnDebugStart(MM_EVENT_FIELD(debug_event, CreateProcessInfo).hFile,
               MM_EVENT_FIELD(debug_event, CreateProcessInfo).hThread);

  CloseHandle(MM_EVENT_FIELD(debug_event, CreateProcessInfo).hFile);
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnExitThreadDebugEvent(DEBUG_EVENT& debug_event) {
  if (!hide_thread_end_) {
    LogF(kLogInfo, "[%.4d] Thread ended (code %lu).", debug_event.dwThreadId,
         MM_EVENT_FIELD(debug_event, ExitThread).dwExitCode);
  }
  const auto it = threads_.find(debug_event.dwThreadId);
  if (it != threads_.end()) {
    CloseHandle(it->second);
    threads_.erase(it);
  }
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnHardwareBreakpointEvent(DEBUG_EVENT& debug_event) {
  const uintptr_t eip = reinterpret_cast<uintptr_t>(
      MM_EVENT_FIELD(debug_event, Exception).ExceptionRecord.ExceptionAddress);
  HANDLE thread_handle = GetThread(debug_event.dwThreadId);

  CONTEXT context{};
  context.ContextFlags =
      CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
  if (!GetThreadContext(thread_handle, &context)) {
    Log(kLogFatal, "GetThreadContext failed");
  }

  if ((((context.Dr6 >> 14) & 1) == 0) &&
      (hw_[0].IsSet() || hw_[1].IsSet() || hw_[2].IsSet() || hw_[3].IsSet())) {
    int slot = -1;
    switch (context.Dr6 & 0xF) {
      case 1:
        slot = 0;
        break;
      case 2:
        slot = 1;
        break;
      case 4:
        slot = 2;
        break;
      case 8:
        slot = 3;
        break;
      default:
        LogF(kLogFatal, "Unknown hwbp at %p (Dr6: %.8llX)",
             reinterpret_cast<void*>(eip), static_cast<uint64_t>(context.Dr6));
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    Breakpoint bp = hw_[slot];
    OnHardwareBreakpoint(thread_handle, bp.address, context);

    // Disable and step over.
    if (bp.type == HwbpType::kExecute && DisableBreakpoint(eip)) {
      UpdateDr(thread_handle);
      context.ContextFlags = CONTEXT_CONTROL;
      context.EFlags |= 0x100;
      if (!SetThreadContext(thread_handle, &context)) {
        Log(kLogFatal, "SetThreadContext failed");
      }
    }

    return DBG_CONTINUE;
  }

  if (soft_bp_reenable_ != 0) {
    // Re-enable soft bp after stepping over it.
    uint8_t int3 = 0xCC;
    WriteProcessMemory(process_.hProcess,
                       reinterpret_cast<void*>(soft_bp_reenable_), &int3, 1,
                       nullptr);
    soft_bp_reenable_ = 0;
    return DBG_CONTINUE;
  }

  return OnSinglestep(eip);
}

DWORD DebuggerCore::OnSinglestep(uintptr_t /*bpAddress*/) {
  // We stepped over a HWBP and may enable it again.
  EnableBreakpoints();
  return DBG_CONTINUE;
}

void DebuggerCore::OnDllLoad(const std::wstring& file_name,
                             void* /*baseAddress*/) {
  if (AsciiLowerCase(WideToUtf8(file_name)).find("aclayers.dll") !=
      std::string::npos) {
    throw std::runtime_error(
        "[FATAL] Compatibility mode screws up the unpacking process.");
  }
}

DWORD DebuggerCore::OnLoadDllDebugEvent(DEBUG_EVENT& debug_event) {
  void* image_name = nullptr;
  wchar_t buffer[MAX_PATH + 1]{};
  std::wstring dll_name;

  if (!ReadProcessMemory(process_.hProcess,
                         MM_EVENT_FIELD(debug_event, LoadDll).lpImageName,
                         &image_name, sizeof(image_name), nullptr) ||
      image_name == nullptr ||
      !ReadProcessMemory(process_.hProcess, image_name, buffer, sizeof(buffer),
                         nullptr)) {
    dll_name = L"?";
  } else {
    dll_name = buffer;
  }

  LogF(kLogInfo, "[%.8llX] Loaded %s",
       static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
           MM_EVENT_FIELD(debug_event, LoadDll).lpBaseOfDll)),
       WideToUtf8(dll_name).c_str());
  OnDllLoad(dll_name, MM_EVENT_FIELD(debug_event, LoadDll).lpBaseOfDll);
  CloseHandle(MM_EVENT_FIELD(debug_event, LoadDll).hFile);
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnExitProcessDebugEvent(DEBUG_EVENT& debug_event) {
  LogF(kLogInfo, "Process ended (code %lu).",
       MM_EVENT_FIELD(debug_event, ExitProcess).dwExitCode);
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnUnloadDllDebugEvent(DEBUG_EVENT& /*debugEvent*/) {
  return DBG_CONTINUE;
}

void DebuggerCore::OnUnsolicitedSoftwareBreakpoint(HANDLE /*thread_handle*/,
                                                   uintptr_t /*bpAddress*/) {
  Log(kLogInfo, "Unsolicited int3");
}

DWORD DebuggerCore::OnOutputDebugStringEvent(DEBUG_EVENT& debug_event) {
  if (MM_EVENT_FIELD(debug_event, DebugString).nDebugStringLength > 0 &&
      MM_EVENT_FIELD(debug_event, DebugString).nDebugStringLength < 256) {
    char buffer[257]{};
    if (Rpm(reinterpret_cast<uintptr_t>(
                MM_EVENT_FIELD(debug_event, DebugString).lpDebugStringData),
            buffer,
            MM_EVENT_FIELD(debug_event, DebugString).nDebugStringLength)) {
      buffer[MM_EVENT_FIELD(debug_event, DebugString).nDebugStringLength] =
          '\0';
      Log(kLogInfo, std::string("[Debug Str] ") + buffer);
    }
  }
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnRipEvent(DEBUG_EVENT& /*debugEvent*/) {
  Log(kLogFatal, "SYSTEM ERROR");
  return DBG_CONTINUE;
}

// --------------------------------------------------------------------------
// Process creation
// --------------------------------------------------------------------------

bool DebuggerCore::PeExecute() {
  if (attach_pid_ != 0) {
    return DebugActiveProcess(attach_pid_) != FALSE;
  }

  PeInspect();

  // If Magicmida is executed with a different working dir, assume the user
  // wants that one as the working dir for the target.
  std::wstring current_dir;
  if (ExtractFilePath(GetExecutablePath()) !=
      IncludeTrailingPathDelimiter(GetCurrentDir())) {
    current_dir = GetCurrentDir();
  } else {
    current_dir = ExtractFilePath(executable_);
    if (!current_dir.empty() && current_dir.back() == L'\\') {
      current_dir.pop_back();
    }
  }

  STARTUPINFOW startup_info{};
  startup_info.cb = sizeof(startup_info);
  startup_info.dwFlags = STARTF_USESHOWWINDOW;
  startup_info.wShowWindow = SW_SHOW;

  std::wstring command_line;
  if (is_dll_) {
    MakeDllExecutable();
    LogF(kLogInfo, "Debugging modified DLL: %s",
         WideToUtf8(dll_executable_).c_str());
    command_line = L"\"" + dll_executable_ + L"\"";
  } else {
    command_line = L"\"" + executable_ + L"\" " + TrimRight(parameters_);
  }

  const DWORD flags = CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_CONSOLE |
                      NORMAL_PRIORITY_CLASS | DEBUG_PROCESS |
                      DEBUG_ONLY_THIS_PROCESS;

  PROCESS_INFORMATION process_info{};
  const BOOL created = CreateProcessW(
      nullptr, command_line.data(), nullptr, nullptr, FALSE, flags, nullptr,
      current_dir.empty() ? nullptr : current_dir.c_str(), &startup_info,
      &process_info);
  process_ = process_info;
  // The debug event supplies its own handle for the initial thread, so the
  // one returned by CreateProcessW is not needed.
  if (process_.hThread != nullptr) {
    CloseHandle(process_.hThread);
    process_.hThread = nullptr;
  }
  return created != FALSE;
}

void DebuggerCore::PeInspect() {
  FileStream file(executable_, FileStream::Mode::kRead);
  uint8_t header[0x1000]{};
  const int64_t file_size = file.Size();
  const size_t to_read =
      std::min<size_t>(sizeof(header), static_cast<size_t>(file_size));
  if (to_read < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("Selected file is not a PE or is malformed");
  }
  file.Read(header, to_read);

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
  if (static_cast<uint32_t>(dos->e_lfanew) > 0xF00 ||
      static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > to_read) {
    throw std::runtime_error("Selected file is not a PE or is malformed");
  }

  const auto* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(header + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("PE file signature mismatch");
  }

  constexpr WORD kExpectedMachine =
      sizeof(void*) == 4 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
  if (nt->FileHeader.Machine != kExpectedMachine) {
    throw std::runtime_error(
        sizeof(void*) == 4
            ? "File is for the wrong architecture, please use the 64-bit "
              "version of Magicmida."
            : "File is for the wrong architecture, please use the 32-bit "
              "version of Magicmida.");
  }

  is_dll_ = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

void DebuggerCore::MakeDllExecutable() {
  // These stubs set up the stack/parameters to stage a call to the DLL
  // entrypoint. Older Themida versions didn't strictly require it, newer ones
  // crash without it.
#if defined(_WIN64)
  constexpr uint8_t kStub[] = {
      0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60,
      0x00, 0x00, 0x00, 0x48, 0x8B, 0x48, 0x10, 0xBA, 0x01, 0x00,
      0x00, 0x00, 0x45, 0x31, 0xC0, 0xE8, 0x00, 0x00, 0x00, 0x00,
  };
#else
  constexpr uint8_t kStub[] = {0x8B, 0x40, 0x08, 0x6A, 0x00, 0x6A, 0x01,
                               0x50, 0xE8, 0x00, 0x00, 0x00, 0x00};
#endif
  constexpr size_t kStubSize = sizeof(kStub);

  dll_executable_ = executable_ + L"MM.exe";
  // Remove a leftover copy from an interrupted previous run before writing
  // the new one.
  DeleteDllCopy();
  if (!CopyFileW(executable_.c_str(), dll_executable_.c_str(), FALSE)) {
    const DWORD error = GetLastError();
    throw std::runtime_error(Format("Copying DLL to %s failed (error %lu)",
                                    WideToUtf8(dll_executable_).c_str(),
                                    error));
  }

  FileStream file(dll_executable_, FileStream::Mode::kReadWrite);
  uint8_t header[0x1000]{};
  const size_t to_read = static_cast<size_t>(
      std::min<int64_t>(static_cast<int64_t>(sizeof(header)), file.Size()));
  if (to_read < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("Copy of the DLL is too small");
  }
  file.Read(header, to_read);

  const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
  if (static_cast<uint32_t>(dos_header->e_lfanew) > 0xF00 ||
      static_cast<size_t>(dos_header->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
          to_read) {
    throw std::runtime_error("Copy of the DLL has a malformed PE header");
  }

  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(header + dos_header->e_lfanew);
  nt->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;
  file.Seek(dos_header->e_lfanew + 22, Stream::Origin::kBegin);
  file.Write(&nt->FileHeader.Characteristics,
             sizeof(nt->FileHeader.Characteristics));

  const uint64_t optional_header_pos = static_cast<uint64_t>(file.Position());

  if ((nt->OptionalHeader.DllCharacteristics & 0x80) != 0) {
    // Disable "Code Integrity Image".
    nt->OptionalHeader.DllCharacteristics &= ~0x80;
    file.Seek(offsetof(IMAGE_OPTIONAL_HEADER, DllCharacteristics),
              Stream::Origin::kCurrent);
    file.Write(&nt->OptionalHeader.DllCharacteristics,
               sizeof(nt->OptionalHeader.DllCharacteristics));
  }

  PeHeader pe(header, to_read);
  PeSection* ep_section =
      pe.GetSectionByVa(nt->OptionalHeader.AddressOfEntryPoint);
  if (ep_section == nullptr || ep_section->header.SizeOfRawData < kStubSize) {
    throw std::runtime_error("Not enough room in EP section");
  }

  file.Seek(ep_section->header.PointerToRawData +
                ep_section->header.SizeOfRawData - kStubSize,
            Stream::Origin::kBegin);

  uint8_t current[kStubSize]{};
  file.Read(current, sizeof(current));
  for (uint8_t value : current) {
    if (value != 0) {
      Log(kLogFatal, "Not enough room in EP section");
      return;
    }
  }

  std::memcpy(current, kStub, kStubSize);
  const uint32_t new_entry_point = ep_section->header.VirtualAddress +
                                   ep_section->header.SizeOfRawData - kStubSize;
  *reinterpret_cast<int32_t*>(current + kStubSize - 4) = static_cast<int32_t>(
      nt->OptionalHeader.AddressOfEntryPoint - (new_entry_point + kStubSize));

  file.Seek(-static_cast<int64_t>(kStubSize), Stream::Origin::kCurrent);
  file.Write(current, sizeof(current));

  nt->OptionalHeader.AddressOfEntryPoint = new_entry_point;
  file.Seek(optional_header_pos +
                offsetof(IMAGE_OPTIONAL_HEADER, AddressOfEntryPoint),
            Stream::Origin::kBegin);
  file.Write(&nt->OptionalHeader.AddressOfEntryPoint,
             sizeof(nt->OptionalHeader.AddressOfEntryPoint));

  Dumper::SwitchSxsManifestType(file, pe, 2, 1);
}

// --------------------------------------------------------------------------
// Memory regions / breakpoints
// --------------------------------------------------------------------------

void DebuggerCore::FetchMemoryRegions() {
  uintptr_t address = 0;
  MEMORY_BASIC_INFORMATION mbi{};
  mbi.RegionSize = 0x1000;

  while (VirtualQueryEx(process_.hProcess, reinterpret_cast<void*>(address),
                        &mbi, sizeof(mbi)) != 0 &&
         address + mbi.RegionSize > address) {
    mem_regions_.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                              mbi.RegionSize);
    address += mbi.RegionSize;
  }
}

bool DebuggerCore::Rpm(uintptr_t address, void* buf, size_t buf_size) {
  return ReadProcessMemory(process_.hProcess, reinterpret_cast<void*>(address),
                           buf, buf_size, nullptr) != FALSE;
}

bool DebuggerCore::IsHwBreakpoint(uintptr_t address) {
  return hw_[0].address == address || hw_[1].address == address ||
         hw_[2].address == address || hw_[3].address == address;
}

void DebuggerCore::SetBreakpoint(uintptr_t address, HwbpType type,
                                 bool refresh_contexts) {
  for (Breakpoint& breakpoint : hw_) {
    if (breakpoint.address == 0) {
      breakpoint.Change(address, type);
      if (refresh_contexts) {
        for (const auto& entry : threads_) {
          UpdateDr(entry.second);
        }
      }
      return;
    }
  }

  throw std::runtime_error("All breakpoints in use");
}

bool DebuggerCore::DisableBreakpoint(uintptr_t address) {
  for (Breakpoint& breakpoint : hw_) {
    if (breakpoint.address == address) {
      breakpoint.disabled = true;
      return true;
    }
  }
  return false;
}

void DebuggerCore::EnableBreakpoints() {
  if (!hw_[0].disabled && !hw_[1].disabled && !hw_[2].disabled &&
      !hw_[3].disabled) {
    return;
  }

  for (Breakpoint& breakpoint : hw_) {
    breakpoint.disabled = false;
  }
  for (const auto& entry : threads_) {
    UpdateDr(entry.second);
  }
}

void DebuggerCore::ResetBreakpoint(uintptr_t address) {
  for (Breakpoint& breakpoint : hw_) {
    if (breakpoint.address == address) {
      breakpoint.address = 0;
    }
  }
  for (const auto& entry : threads_) {
    UpdateDr(entry.second);
  }
}

void DebuggerCore::ApplyDebugRegisters(CONTEXT& context) {
  ULONG_PTR mask = 0;

  context.Dr0 = hw_[0].address;
  if (hw_[0].IsSet()) {
    mask = 1;
  }

  context.Dr1 = hw_[1].address;
  if (hw_[1].IsSet()) {
    mask |= static_cast<ULONG_PTR>(1) << 2;
  }

  context.Dr2 = hw_[2].address;
  if (hw_[2].IsSet()) {
    mask |= static_cast<ULONG_PTR>(1) << 4;
  }

  context.Dr3 = hw_[3].address;
  if (hw_[3].IsSet()) {
    mask |= static_cast<ULONG_PTR>(1) << 6;
  }

  context.Dr6 &= ~static_cast<decltype(context.Dr6)>(0x4000);
  context.Dr7 = static_cast<decltype(context.Dr7)>(
      mask | (static_cast<uint64_t>(hw_[0].type) << 16) |
      (static_cast<uint64_t>(hw_[1].type) << 20) |
      (static_cast<uint64_t>(hw_[2].type) << 24) |
      (static_cast<uint64_t>(hw_[3].type) << 28));
}

void DebuggerCore::UpdateDr(HANDLE thread) {
  CONTEXT context{};
  context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (GetThreadContext(thread, &context)) {
    ApplyDebugRegisters(context);
    SetThreadContext(thread, &context);
  } else {
    Log(kLogFatal, "GetThreadContext failed");
  }
}

bool DebuggerCore::WriteByte(uintptr_t address, uint8_t value) {
  DWORD old_protect = 0;
  const BOOL result =
      VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(address), 1,
                       PAGE_EXECUTE_READWRITE, &old_protect) &&
      WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(address),
                         &value, 1, nullptr) &&
      VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(address), 1,
                       old_protect, &old_protect);
  FlushInstructionCache(process_.hProcess, reinterpret_cast<void*>(address), 1);
  return result != FALSE;
}

// --------------------------------------------------------------------------
// Software breakpoints
// --------------------------------------------------------------------------

DWORD DebuggerCore::OnSoftwareBreakpointEvent(DEBUG_EVENT& debug_event) {
  const uintptr_t eip = reinterpret_cast<uintptr_t>(
      MM_EVENT_FIELD(debug_event, Exception).ExceptionRecord.ExceptionAddress);
  HANDLE thread_handle = GetThread(debug_event.dwThreadId);

  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL;
  GetThreadContext(thread_handle, &context);
#if defined(_WIN64)
  --context.Rip;
#else
  --context.Eip;
#endif
  SetThreadContext(thread_handle, &context);

  const uint8_t original = soft_bps_.at(eip);
  // Before OnSoftwareBreakpoint (child implementations may write to EIP!).
  if (!WriteByte(eip, original)) {
    Log(kLogFatal, "Restoring original byte failed");
  }

  const SoftBpAction action = OnSoftwareBreakpoint(thread_handle, eip);

  if (action == SoftBpAction::kClearContinue) {
    soft_bps_.erase(eip);
  } else if (action == SoftBpAction::kKeepContinue) {
    // Keep, single step.
#if defined(_WIN64)
    soft_bp_reenable_ = context.Rip;
#else
    soft_bp_reenable_ = context.Eip;
#endif
    context.EFlags |= 0x100;
    SetThreadContext(thread_handle, &context);
  } else if (action == SoftBpAction::kKeepContinueNoStep) {
    if (!WriteByte(eip, 0xCC)) {
      Log(kLogFatal, "KeepContinueNoStep failed");
    }
  }

  return DBG_CONTINUE;
}

void DebuggerCore::SetSoftBp(uintptr_t address) {
  uint8_t original = 0;
  if (!ReadProcessMemory(process_.hProcess, reinterpret_cast<void*>(address),
                         &original, 1, nullptr)) {
    throw std::runtime_error(Format("Read for soft bp at %llX failed",
                                    static_cast<uint64_t>(address)));
  }

  const auto it = soft_bps_.find(address);
  if (it != soft_bps_.end()) {
    if (original != 0xCC) {
      LogF(kLogFatal, "Soft bp inconsistency at %llX!",
           static_cast<uint64_t>(address));
    }
    return;
  }

  soft_bps_[address] = original;

  if (!WriteByte(address, 0xCC)) {
    throw std::runtime_error(Format("Write for soft bp at %llX failed",
                                    static_cast<uint64_t>(address)));
  }

  FlushInstructionCache(process_.hProcess, reinterpret_cast<void*>(address), 1);
}

void DebuggerCore::SoftBpClear() {
  for (const auto& entry : soft_bps_) {
    WriteByte(entry.first, entry.second);
  }
  soft_bps_.clear();
}

}  // namespace magicmida
