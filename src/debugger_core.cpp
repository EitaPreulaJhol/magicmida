// Magicmida - C++ port
// Debugger primitives: process creation, debug loop, HW/SW breakpoints.
#include "debugger_core.h"

#include "dumper.h"
#include "pe_info.h"
#include "scyllahide.h"
#include "stream.h"

#include <algorithm>
#include <cstring>

namespace magicmida {
namespace {

constexpr uintptr_t OFFSET_IMAGEBASE = sizeof(void*) == 4 ? 8 : 16;
constexpr uintptr_t OFFSET_SHIMDATA = sizeof(void*) == 4 ? 0x1E8 : 0x2D8;

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

DebuggerCore::DebuggerCore(DWORD attachPid) : attachPid_(attachPid) {}

// --------------------------------------------------------------------------
// Debug loop
// --------------------------------------------------------------------------

void DebuggerCore::Run() {
  try {
    if (!PEExecute()) {
      throw std::runtime_error(Format("CreateProcess failed (error %lu)",
                                      GetLastError()));
    }
  } catch (const std::exception& error) {
    LogF(ltFatal, "Creating the process failed: %s", error.what());
    if (isDll_) {
      DeleteFileW(dllExecutable_.c_str());
    }
    CloseProcessHandles();
    return;
  }

  bool processExited = false;
  bool stop = false;
  try {
    DWORD status = DBG_CONTINUE;
    for (;;) {
      DEBUG_EVENT debugEvent{};
      if (!WaitForDebugEvent(&debugEvent, 200)) {
        const DWORD error = GetLastError();
        if (error == ERROR_SEM_TIMEOUT) {
          if (IsCancellationRequested()) {
            Log(ltWarning, "Cancellation requested; stopping.");
            stop = true;
            break;
          }
          continue;
        }
        LogF(ltFatal, "OS Error: WaitForDebugEvent failed (error %lu)",
             error);
        break;
      }

      if (IsCancellationRequested()) {
        Log(ltWarning, "Cancellation requested; stopping.");
        stop = true;
        break;
      }

      currentThreadId_ = debugEvent.dwThreadId;

      switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
          status = DBG_EXCEPTION_NOT_HANDLED;
          switch (MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION:
              status = OnAccessViolation(
                  GetThread(debugEvent.dwThreadId),
                  MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord);
              break;

            case EXCEPTION_BREAKPOINT:
              if (softBPs_.find(reinterpret_cast<uintptr_t>(
                      MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionAddress)) !=
                  softBPs_.end()) {
                status = OnSoftwareBreakpointEvent(debugEvent);
              } else {
                OnUnsolicitedSoftwareBreakpoint(
                    GetThread(debugEvent.dwThreadId),
                    reinterpret_cast<uintptr_t>(
                        MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionAddress));
              }
              break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
              // First chance: pass this on to the system.
              break;

            case EXCEPTION_SINGLE_STEP:
              status = OnHardwareBreakpointEvent(debugEvent);
              break;

            case DBG_CONTROL_C:
              break;

            default:
              if (MM_EVENT_FIELD(debugEvent, Exception).dwFirstChance == 0) {
                LogF(ltFatal, "dwFirstChance = 0");
                stop = true;
                break;
              }
              LogF(ltInfo, "Code 0x%.8X at 0x%p",
                   MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionCode,
                   MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionAddress);
              status = DBG_EXCEPTION_NOT_HANDLED;
              break;
          }
          break;
        }

        case CREATE_THREAD_DEBUG_EVENT:
          status = OnCreateThreadDebugEvent(debugEvent);
          break;

        case CREATE_PROCESS_DEBUG_EVENT:
          status = OnCreateProcessDebugEvent(debugEvent);
          break;

        case EXIT_THREAD_DEBUG_EVENT:
          status = OnExitThreadDebugEvent(debugEvent);
          break;

        case EXIT_PROCESS_DEBUG_EVENT:
          status = OnExitProcessDebugEvent(debugEvent);
          ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                             status);
          processExited = true;
          break;

        case LOAD_DLL_DEBUG_EVENT:
          status = OnLoadDllDebugEvent(debugEvent);
          break;

        case UNLOAD_DLL_DEBUG_EVENT:
          status = OnUnloadDllDebugEvent(debugEvent);
          break;

        case OUTPUT_DEBUG_STRING_EVENT:
          status = OnOutputDebugStringEvent(debugEvent);
          break;

        case RIP_EVENT:
          status = OnRipEvent(debugEvent);
          break;

        default:
          break;
      }

      if (processExited || stop) {
        break;
      }

      ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, status);
    }
  } catch (const std::exception& error) {
    LogF(ltFatal, "Critical error in debug loop: %s", error.what());
  }

  if (!processExited) {
    TerminateDebuggee();
  }

  if (isDll_) {
    if (process_.hProcess != nullptr) {
      WaitForSingleObject(process_.hProcess, 5000);
    }
    DeleteFileW(dllExecutable_.c_str());
  }

  CloseProcessHandles();
}

void DebuggerCore::TerminateDebuggee() {
  if (process_.hProcess == nullptr) {
    return;
  }

  DWORD exitCode = 0;
  if (GetExitCodeProcess(process_.hProcess, &exitCode) &&
      exitCode == STILL_ACTIVE) {
    Log(ltWarning, "Terminating the target process.");
    TerminateProcess(process_.hProcess, 1);
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
    Log(ltInfo, "Detached.");
  } else {
    Log(ltFatal, "Detaching failed.");
  }
}

HANDLE DebuggerCore::GetThread(DWORD threadId) {
  const auto it = threads_.find(threadId);
  if (it == threads_.end()) {
    throw std::runtime_error(Format("Thread %lu not found", threadId));
  }
  return it->second;
}

// --------------------------------------------------------------------------
// Debug events
// --------------------------------------------------------------------------

DWORD DebuggerCore::OnCreateThreadDebugEvent(DEBUG_EVENT& debugEvent) {
  LogF(ltInfo, "[%.4d] Thread started (%p).", debugEvent.dwThreadId,
       MM_EVENT_FIELD(debugEvent, CreateThread).lpStartAddress);

  const auto it = threads_.find(debugEvent.dwThreadId);
  if (it != threads_.end()) {
    CloseHandle(it->second);
  }
  threads_[debugEvent.dwThreadId] = MM_EVENT_FIELD(debugEvent, CreateThread).hThread;
  UpdateDR(MM_EVENT_FIELD(debugEvent, CreateThread).hThread);

  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnAccessViolation(HANDLE /*hThread*/,
                                      const EXCEPTION_RECORD& exceptionRecord) {
  LogF(ltInfo, "[%lu] Access violation at 0x%p: %s of 0x%p", currentThreadId_,
       exceptionRecord.ExceptionAddress,
       AccessViolationFlagToStr(
           static_cast<uint8_t>(exceptionRecord.ExceptionInformation[0]))
           .c_str(),
       reinterpret_cast<void*>(exceptionRecord.ExceptionInformation[1]));
  return DBG_EXCEPTION_NOT_HANDLED;
}

DWORD DebuggerCore::OnCreateProcessDebugEvent(DEBUG_EVENT& debugEvent) {
  LogF(ltInfo, "Running on Windows build %u", GetWindowsBuildNumber());
  LogF(ltInfo, "Debug session launched (PID: %lu, TID: %lu)",
       debugEvent.dwProcessId, debugEvent.dwThreadId);

  const HANDLE eventProcess =
      MM_EVENT_FIELD(debugEvent, CreateProcessInfo).hProcess;
  if (process_.hProcess != nullptr && process_.hProcess != eventProcess) {
    // CreateProcessW returned a handle to the same process; the debug event
    // handle replaces it for the rest of the session.
    CloseHandle(process_.hProcess);
  }
  process_.hProcess = eventProcess;
  process_.dwProcessId = debugEvent.dwProcessId;

  ProcessBasicInformation pbi{};
  NtQueryInformationProcess(process_.hProcess, 0, &pbi, sizeof(pbi), nullptr);
  LogF(ltInfo, "PEB: %p", pbi.PebBaseAddress);

  uint8_t byteValue = 0;
  if (ReadProcessMemory(process_.hProcess,
                        static_cast<uint8_t*>(pbi.PebBaseAddress) + 2,
                        &byteValue, 1, nullptr)) {
    if (byteValue == 1) {
      Log(ltGood, "Patching PEB.BeingDebugged");
      byteValue = 0;
      WriteProcessMemory(process_.hProcess,
                         static_cast<uint8_t*>(pbi.PebBaseAddress) + 2,
                         &byteValue, 1, nullptr);
    }
  } else {
    Log(ltFatal, "Reading PEB failed");
  }

  if (ReadProcessMemory(process_.hProcess,
                        static_cast<uint8_t*>(pbi.PebBaseAddress) +
                            OFFSET_IMAGEBASE,
                        &imageBase_, sizeof(imageBase_), nullptr)) {
    LogF(ltInfo, "Process Image Base: %p",
         reinterpret_cast<void*>(imageBase_));
  } else {
    throw std::runtime_error("Reading process image base failed");
  }

  uintptr_t shimData = 0;
  if (ReadProcessMemory(process_.hProcess,
                        static_cast<uint8_t*>(pbi.PebBaseAddress) +
                            OFFSET_SHIMDATA,
                        &shimData, sizeof(shimData), nullptr) &&
      shimData != 0) {
    shimData = 0;
    if (WriteProcessMemory(process_.hProcess,
                           static_cast<uint8_t*>(pbi.PebBaseAddress) +
                               OFFSET_SHIMDATA,
                           &shimData, sizeof(shimData), nullptr)) {
      Log(ltInfo, "Cleared PEB.pShimData to prevent apphelp hooks");
    }
  }

  threads_[debugEvent.dwThreadId] = MM_EVENT_FIELD(debugEvent, CreateProcessInfo).hThread;

  OnDebugStart(MM_EVENT_FIELD(debugEvent, CreateProcessInfo).hFile,
               MM_EVENT_FIELD(debugEvent, CreateProcessInfo).hThread);

  CloseHandle(MM_EVENT_FIELD(debugEvent, CreateProcessInfo).hFile);
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnExitThreadDebugEvent(DEBUG_EVENT& debugEvent) {
  if (!hideThreadEnd_) {
    LogF(ltInfo, "[%.4d] Thread ended (code %lu).", debugEvent.dwThreadId,
         MM_EVENT_FIELD(debugEvent, ExitThread).dwExitCode);
  }
  const auto it = threads_.find(debugEvent.dwThreadId);
  if (it != threads_.end()) {
    CloseHandle(it->second);
    threads_.erase(it);
  }
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnHardwareBreakpointEvent(DEBUG_EVENT& debugEvent) {
  const uintptr_t eip = reinterpret_cast<uintptr_t>(
      MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionAddress);
  HANDLE hThread = GetThread(debugEvent.dwThreadId);

  CONTEXT context{};
  context.ContextFlags =
      CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
  if (!GetThreadContext(hThread, &context)) {
    Log(ltFatal, "GetThreadContext failed");
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
        LogF(ltFatal, "Unknown hwbp at %p (Dr6: %.8llX)",
             reinterpret_cast<void*>(eip),
             static_cast<unsigned long long>(context.Dr6));
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    Breakpoint bp = hw_[slot];
    OnHardwareBreakpoint(hThread, bp.Address, context);

    // Disable and step over.
    if (bp.Type == HWBPType::Execute && DisableBreakpoint(eip)) {
      UpdateDR(hThread);
      context.ContextFlags = CONTEXT_CONTROL;
      context.EFlags |= 0x100;
      if (!SetThreadContext(hThread, &context)) {
        Log(ltFatal, "SetThreadContext failed");
      }
    }

    return DBG_CONTINUE;
  }

  if (softBPReenable_ != 0) {
    // Re-enable soft bp after stepping over it.
    uint8_t int3 = 0xCC;
    WriteProcessMemory(process_.hProcess,
                       reinterpret_cast<void*>(softBPReenable_), &int3, 1,
                       nullptr);
    softBPReenable_ = 0;
    return DBG_CONTINUE;
  }

  return OnSinglestep(eip);
}

DWORD DebuggerCore::OnSinglestep(uintptr_t /*bpAddress*/) {
  // We stepped over a HWBP and may enable it again.
  EnableBreakpoints();
  return DBG_CONTINUE;
}

void DebuggerCore::OnDLLLoad(const std::wstring& fileName,
                             void* /*baseAddress*/) {
  if (AsciiLowerCase(WideToUtf8(fileName)).find("aclayers.dll") !=
      std::string::npos) {
    throw std::runtime_error(
        "[FATAL] Compatibility mode screws up the unpacking process.");
  }
}

DWORD DebuggerCore::OnLoadDllDebugEvent(DEBUG_EVENT& debugEvent) {
  void* imageName = nullptr;
  wchar_t buffer[MAX_PATH + 1]{};
  std::wstring dllName;

  if (!ReadProcessMemory(process_.hProcess, MM_EVENT_FIELD(debugEvent, LoadDll).lpImageName,
                         &imageName, sizeof(imageName), nullptr) ||
      imageName == nullptr ||
      !ReadProcessMemory(process_.hProcess, imageName, buffer, sizeof(buffer),
                         nullptr)) {
    dllName = L"?";
  } else {
    dllName = buffer;
  }

  LogF(ltInfo, "[%.8llX] Loaded %s",
       static_cast<unsigned long long>(
           reinterpret_cast<uintptr_t>(MM_EVENT_FIELD(debugEvent, LoadDll).lpBaseOfDll)),
       WideToUtf8(dllName).c_str());
  OnDLLLoad(dllName, MM_EVENT_FIELD(debugEvent, LoadDll).lpBaseOfDll);
  CloseHandle(MM_EVENT_FIELD(debugEvent, LoadDll).hFile);
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnExitProcessDebugEvent(DEBUG_EVENT& debugEvent) {
  LogF(ltInfo, "Process ended (code %lu).", MM_EVENT_FIELD(debugEvent, ExitProcess).dwExitCode);
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnUnloadDllDebugEvent(DEBUG_EVENT& /*debugEvent*/) {
  return DBG_CONTINUE;
}

void DebuggerCore::OnUnsolicitedSoftwareBreakpoint(HANDLE /*hThread*/,
                                                   uintptr_t /*bpAddress*/) {
  Log(ltInfo, "Unsolicited int3");
}

DWORD DebuggerCore::OnOutputDebugStringEvent(DEBUG_EVENT& debugEvent) {
  if (MM_EVENT_FIELD(debugEvent, DebugString).nDebugStringLength > 0 &&
      MM_EVENT_FIELD(debugEvent, DebugString).nDebugStringLength < 256) {
    char buffer[257]{};
    if (RPM(reinterpret_cast<uintptr_t>(MM_EVENT_FIELD(debugEvent, DebugString).lpDebugStringData),
            buffer, MM_EVENT_FIELD(debugEvent, DebugString).nDebugStringLength)) {
      buffer[MM_EVENT_FIELD(debugEvent, DebugString).nDebugStringLength] = '\0';
      Log(ltInfo, std::string("[Debug Str] ") + buffer);
    }
  }
  return DBG_CONTINUE;
}

DWORD DebuggerCore::OnRipEvent(DEBUG_EVENT& /*debugEvent*/) {
  Log(ltFatal, "SYSTEM ERROR");
  return DBG_CONTINUE;
}

// --------------------------------------------------------------------------
// Process creation
// --------------------------------------------------------------------------

bool DebuggerCore::PEExecute() {
  if (attachPid_ != 0) {
    return DebugActiveProcess(attachPid_) != FALSE;
  }

  PEInspect();

  // If Magicmida is executed with a different working dir, assume the user
  // wants that one as the working dir for the target.
  std::wstring currentDir;
  if (ExtractFilePath(GetExecutablePath()) !=
      IncludeTrailingPathDelimiter(GetCurrentDir())) {
    currentDir = GetCurrentDir();
  } else {
    currentDir = ExtractFilePath(executable_);
    if (!currentDir.empty() && currentDir.back() == L'\\') {
      currentDir.pop_back();
    }
  }

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_SHOW;

  std::wstring commandLine;
  if (isDll_) {
    MakeDLLExecutable();
    LogF(ltInfo, "Debugging modified DLL: %s",
         WideToUtf8(dllExecutable_).c_str());
    commandLine = L"\"" + dllExecutable_ + L"\"";
  } else {
    commandLine = L"\"" + executable_ + L"\" " + TrimRight(parameters_);
  }

  const DWORD flags = CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_CONSOLE |
                      NORMAL_PRIORITY_CLASS | DEBUG_PROCESS |
                      DEBUG_ONLY_THIS_PROCESS;

  PROCESS_INFORMATION processInfo{};
  const BOOL created =
      CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE, flags,
                     nullptr, currentDir.empty() ? nullptr : currentDir.c_str(),
                     &startupInfo, &processInfo);
  process_ = processInfo;
  // The debug event supplies its own handle for the initial thread, so the
  // one returned by CreateProcessW is not needed.
  if (process_.hThread != nullptr) {
    CloseHandle(process_.hThread);
    process_.hThread = nullptr;
  }
  return created != FALSE;
}

void DebuggerCore::PEInspect() {
  FileStream file(executable_, FileStream::Mode::Read);
  uint8_t header[0x1000]{};
  const int64_t fileSize = file.Size();
  const size_t toRead =
      std::min<size_t>(sizeof(header), static_cast<size_t>(fileSize));
  if (toRead < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("Selected file is not a PE or is malformed");
  }
  file.Read(header, toRead);

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
  if (static_cast<uint32_t>(dos->e_lfanew) > 0xF00 ||
      static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > toRead) {
    throw std::runtime_error("Selected file is not a PE or is malformed");
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(header + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("PE file signature mismatch");
  }

  constexpr WORD expectedMachine =
      sizeof(void*) == 4 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
  if (nt->FileHeader.Machine != expectedMachine) {
    throw std::runtime_error(
        sizeof(void*) == 4
            ? "File is for the wrong architecture, please use the 64-bit "
              "version of Magicmida."
            : "File is for the wrong architecture, please use the 32-bit "
              "version of Magicmida.");
  }

  isDll_ = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

void DebuggerCore::MakeDLLExecutable() {
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
  constexpr uint8_t kStub[] = {0x8B, 0x40, 0x08, 0x6A, 0x00, 0x6A,
                               0x01, 0x50, 0xE8, 0x00, 0x00, 0x00,
                               0x00};
#endif
  constexpr size_t kStubSize = sizeof(kStub);

  dllExecutable_ = executable_ + L"MM.exe";
  if (!CopyFileW(executable_.c_str(), dllExecutable_.c_str(), FALSE)) {
    throw std::runtime_error("Copying DLL failed");
  }

  FileStream file(dllExecutable_, FileStream::Mode::ReadWrite);
  uint8_t header[0x1000]{};
  const size_t toRead = static_cast<size_t>(
      std::min<int64_t>(static_cast<int64_t>(sizeof(header)), file.Size()));
  if (toRead < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("Copy of the DLL is too small");
  }
  file.Read(header, toRead);

  const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
  if (static_cast<uint32_t>(dosHeader->e_lfanew) > 0xF00 ||
      static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
          toRead) {
    throw std::runtime_error("Copy of the DLL has a malformed PE header");
  }

  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(header + dosHeader->e_lfanew);
  nt->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;
  file.Seek(dosHeader->e_lfanew + 22, Stream::Origin::Begin);
  file.Write(&nt->FileHeader.Characteristics,
             sizeof(nt->FileHeader.Characteristics));

  const uint64_t optionalHeaderPos = static_cast<uint64_t>(file.Position());

  if ((nt->OptionalHeader.DllCharacteristics & 0x80) != 0) {
    // Disable "Code Integrity Image".
    nt->OptionalHeader.DllCharacteristics &= ~0x80;
    file.Seek(offsetof(IMAGE_OPTIONAL_HEADER, DllCharacteristics),
              Stream::Origin::Current);
    file.Write(&nt->OptionalHeader.DllCharacteristics,
               sizeof(nt->OptionalHeader.DllCharacteristics));
  }

  PEHeader pe(header, toRead);
  PESection* epSection = pe.GetSectionByVA(nt->OptionalHeader.AddressOfEntryPoint);
  if (epSection == nullptr || epSection->Header.SizeOfRawData < kStubSize) {
    throw std::runtime_error("Not enough room in EP section");
  }

  file.Seek(epSection->Header.PointerToRawData +
                epSection->Header.SizeOfRawData - kStubSize,
            Stream::Origin::Begin);

  uint8_t current[kStubSize]{};
  file.Read(current, sizeof(current));
  for (uint8_t value : current) {
    if (value != 0) {
      Log(ltFatal, "Not enough room in EP section");
      return;
    }
  }

  std::memcpy(current, kStub, kStubSize);
  const uint32_t newEntryPoint = epSection->Header.VirtualAddress +
                                 epSection->Header.SizeOfRawData - kStubSize;
  *reinterpret_cast<int32_t*>(current + kStubSize - 4) =
      static_cast<int32_t>(nt->OptionalHeader.AddressOfEntryPoint -
                           (newEntryPoint + kStubSize));

  file.Seek(-static_cast<int64_t>(kStubSize), Stream::Origin::Current);
  file.Write(current, sizeof(current));

  nt->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
  file.Seek(optionalHeaderPos +
                offsetof(IMAGE_OPTIONAL_HEADER, AddressOfEntryPoint),
            Stream::Origin::Begin);
  file.Write(&nt->OptionalHeader.AddressOfEntryPoint,
             sizeof(nt->OptionalHeader.AddressOfEntryPoint));

  Dumper::SwitchSxSManifestType(file, pe, 2, 1);
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
    memRegions_.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                             mbi.RegionSize);
    address += mbi.RegionSize;
  }
}

bool DebuggerCore::RPM(uintptr_t address, void* buf, size_t bufSize) {
  return ReadProcessMemory(process_.hProcess,
                           reinterpret_cast<void*>(address), buf, bufSize,
                           nullptr) != FALSE;
}

bool DebuggerCore::IsHWBreakpoint(uintptr_t address) {
  return hw_[0].Address == address || hw_[1].Address == address ||
         hw_[2].Address == address || hw_[3].Address == address;
}

void DebuggerCore::SetBreakpoint(uintptr_t address, HWBPType type,
                                 bool refreshContexts) {
  for (Breakpoint& breakpoint : hw_) {
    if (breakpoint.Address == 0) {
      breakpoint.Change(address, type);
      if (refreshContexts) {
        for (const auto& entry : threads_) {
          UpdateDR(entry.second);
        }
      }
      return;
    }
  }

  throw std::runtime_error("All breakpoints in use");
}

bool DebuggerCore::DisableBreakpoint(uintptr_t address) {
  for (Breakpoint& breakpoint : hw_) {
    if (breakpoint.Address == address) {
      breakpoint.Disabled = true;
      return true;
    }
  }
  return false;
}

void DebuggerCore::EnableBreakpoints() {
  if (!hw_[0].Disabled && !hw_[1].Disabled && !hw_[2].Disabled &&
      !hw_[3].Disabled) {
    return;
  }

  for (Breakpoint& breakpoint : hw_) {
    breakpoint.Disabled = false;
  }
  for (const auto& entry : threads_) {
    UpdateDR(entry.second);
  }
}

void DebuggerCore::ResetBreakpoint(uintptr_t address) {
  for (Breakpoint& breakpoint : hw_) {
    if (breakpoint.Address == address) {
      breakpoint.Address = 0;
    }
  }
  for (const auto& entry : threads_) {
    UpdateDR(entry.second);
  }
}

void DebuggerCore::ApplyDebugRegisters(CONTEXT& context) {
  ULONG_PTR mask = 0;

  context.Dr0 = hw_[0].Address;
  if (hw_[0].IsSet()) {
    mask = 1;
  }

  context.Dr1 = hw_[1].Address;
  if (hw_[1].IsSet()) {
    mask |= static_cast<ULONG_PTR>(1) << 2;
  }

  context.Dr2 = hw_[2].Address;
  if (hw_[2].IsSet()) {
    mask |= static_cast<ULONG_PTR>(1) << 4;
  }

  context.Dr3 = hw_[3].Address;
  if (hw_[3].IsSet()) {
    mask |= static_cast<ULONG_PTR>(1) << 6;
  }

  context.Dr6 &= ~static_cast<decltype(context.Dr6)>(0x4000);
  context.Dr7 = static_cast<decltype(context.Dr7)>(
      mask | (static_cast<uint64_t>(hw_[0].Type) << 16) |
      (static_cast<uint64_t>(hw_[1].Type) << 20) |
      (static_cast<uint64_t>(hw_[2].Type) << 24) |
      (static_cast<uint64_t>(hw_[3].Type) << 28));
}

void DebuggerCore::UpdateDR(HANDLE thread) {
  CONTEXT context{};
  context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (GetThreadContext(thread, &context)) {
    ApplyDebugRegisters(context);
    SetThreadContext(thread, &context);
  } else {
    Log(ltFatal, "GetThreadContext failed");
  }
}

bool DebuggerCore::WriteByte(uintptr_t address, uint8_t value) {
  DWORD oldProtect = 0;
  const BOOL result =
      VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(address), 1,
                       PAGE_EXECUTE_READWRITE, &oldProtect) &&
      WriteProcessMemory(process_.hProcess,
                         reinterpret_cast<void*>(address), &value, 1, nullptr) &&
      VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(address), 1,
                       oldProtect, &oldProtect);
  FlushInstructionCache(process_.hProcess, reinterpret_cast<void*>(address), 1);
  return result != FALSE;
}

// --------------------------------------------------------------------------
// Software breakpoints
// --------------------------------------------------------------------------

DWORD DebuggerCore::OnSoftwareBreakpointEvent(DEBUG_EVENT& debugEvent) {
  const uintptr_t eip = reinterpret_cast<uintptr_t>(
      MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionAddress);
  HANDLE hThread = GetThread(debugEvent.dwThreadId);

  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL;
  GetThreadContext(hThread, &context);
#if defined(_WIN64)
  --context.Rip;
#else
  --context.Eip;
#endif
  SetThreadContext(hThread, &context);

  const uint8_t original = softBPs_.at(eip);
  // Before OnSoftwareBreakpoint (child implementations may write to EIP!).
  if (!WriteByte(eip, original)) {
    Log(ltFatal, "Restoring original byte failed");
  }

  const SoftBPAction action = OnSoftwareBreakpoint(hThread, eip);

  if (action == SoftBPAction::ClearContinue) {
    softBPs_.erase(eip);
  } else if (action == SoftBPAction::KeepContinue) {
    // Keep, single step.
#if defined(_WIN64)
    softBPReenable_ = context.Rip;
#else
    softBPReenable_ = context.Eip;
#endif
    context.EFlags |= 0x100;
    SetThreadContext(hThread, &context);
  } else if (action == SoftBPAction::KeepContinueNoStep) {
    if (!WriteByte(eip, 0xCC)) {
      Log(ltFatal, "KeepContinueNoStep failed");
    }
  }

  return DBG_CONTINUE;
}

void DebuggerCore::SetSoftBP(uintptr_t address) {
  uint8_t original = 0;
  if (!ReadProcessMemory(process_.hProcess,
                         reinterpret_cast<void*>(address), &original, 1,
                         nullptr)) {
    throw std::runtime_error(
        Format("Read for soft bp at %llX failed",
               static_cast<unsigned long long>(address)));
  }

  const auto it = softBPs_.find(address);
  if (it != softBPs_.end()) {
    if (original != 0xCC) {
      LogF(ltFatal, "Soft bp inconsistency at %llX!",
           static_cast<unsigned long long>(address));
    }
    return;
  }

  softBPs_[address] = original;

  if (!WriteByte(address, 0xCC)) {
    throw std::runtime_error(
        Format("Write for soft bp at %llX failed",
               static_cast<unsigned long long>(address)));
  }

  FlushInstructionCache(process_.hProcess,
                        reinterpret_cast<void*>(address), 1);
}

void DebuggerCore::SoftBPClear() {
  for (const auto& entry : softBPs_) {
    WriteByte(entry.first, entry.second);
  }
  softBPs_.clear();
}

}  // namespace magicmida
