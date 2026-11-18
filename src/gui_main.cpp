// Magicmida - C++ port
// Native Win32 GUI front-end.
#include "common.h"
#include "patcher.h"
#include "pe_report.h"
#include "reloc_fix.h"
#include "scyllahide.h"
#include "stream.h"

#if defined(_WIN64)
#include "themida64.h"
#else
#include "themida32.h"
#endif

#include <windows.h>

#include <commdlg.h>
#include <richedit.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <vector>

namespace magicmida {
namespace {

constexpr wchar_t kWindowClass[] = L"MagicmidaGuiWindow";
constexpr wchar_t kWindowTitle[] = L"Magicmida";
constexpr WORD kWorkerResourceId = 103;
constexpr WORD kRtRcData = 10;
constexpr UINT_PTR kTargetTimerId = 1;

enum ControlId : int {
  kTargetLabel = 100,
  kTarget,
  kBrowse,
  kCommandLabel,
  kCommand,
  kPidLabel,
  kPid,
  kStart,
  kCancel,
  kLog,
  kStatus,
};

enum MenuId : int {
  kMenuOpen = 200,
  kMenuClearLog,
  kMenuSaveLog,
  kMenuCopyLog,
  kMenuExit,
  kMenuAbout,
  kMenuAdvDataSections,
  kMenuAdvNoScylla,
  kMenuAdvFixRelocs,
};

constexpr UINT kMsgLog = WM_APP + 1;
constexpr UINT kMsgDone = WM_APP + 2;
constexpr UINT kMsgStatus = WM_APP + 3;

struct LogEntry {
  LogMsgType type;
  std::string text;
};

struct AppState {
  HINSTANCE instance = nullptr;
  HWND hwnd = nullptr;
  HMENU menu = nullptr;
  HMENU advanced_menu = nullptr;
  HWND target_label = nullptr;
  HWND target = nullptr;
  HWND browse = nullptr;
  HWND command_label = nullptr;
  HWND command = nullptr;
  HWND pid_label = nullptr;
  HWND pid = nullptr;
  HWND start = nullptr;
  HWND cancel = nullptr;
  HWND log = nullptr;
  HWND status = nullptr;
  bool create_data_sections = false;
  bool disable_scylla = false;
  bool fix_relocations = false;
  HANDLE cancel_event = nullptr;
  std::wstring cancel_event_name;
  HFONT ui_font = nullptr;
  HFONT log_font = nullptr;
  HACCEL accel = nullptr;
  HANDLE worker = nullptr;
  bool running = false;
};

// Function-local pointers to heap objects that are intentionally never
// destroyed: static objects with non-trivial destructors are not allowed.
AppState& App() {
  static AppState* app = new AppState;
  return *app;
}

int& DpiScale() {
  static int dpi = 96;
  return dpi;
}

int Dip(int value) {
  return MulDiv(value, DpiScale(), 96);
}

enum class Command {
  kUnpack = 0,
  kShrink = 1,
  kMkData = 2,
  kDumpCode = 3,
  kInfo = 4,
};

struct Job {
  Command command = Command::kUnpack;
  std::wstring target;
  bool create_data_sections = false;
  bool use_scylla_hide = true;
  bool fix_relocations = false;
  bool use_worker = false;
  DWORD pid = 0;
};

std::wstring GetText(HWND control) {
  const int length = GetWindowTextLengthW(control);
  std::wstring text(static_cast<size_t>(length) + 1, L'\0');
  if (length > 0) {
    GetWindowTextW(control, text.data(), length + 1);
  }
  text.resize(static_cast<size_t>(length));
  return text;
}

void DisableVisualStyles() {
  // SetThemeAppProperties(0) is available from XP onwards.  On Windows 2000
  // uxtheme.dll is not present, and controls are classic by default anyway.
  HMODULE uxtheme = LoadLibraryW(L"uxtheme.dll");
  if (uxtheme == nullptr) {
    return;
  }
  // NOLINTNEXTLINE(readability/casting)
  using SetThemeAppPropertiesFn = void(WINAPI*)(DWORD);
  const auto set_theme_app_properties =
      reinterpret_cast<SetThemeAppPropertiesFn>(
          GetProcAddress(uxtheme, "SetThemeAppProperties"));
  if (set_theme_app_properties != nullptr) {
    set_theme_app_properties(0);
  }
}

void SetStatus(const wchar_t* text) {
  if (App().status != nullptr) {
    SetWindowTextW(App().status, text);
  }
}

const char* LogPrefix(LogMsgType type) {
  switch (type) {
    case LogMsgType::kGood:
      return "[Good] ";
    case LogMsgType::kWarning:
      return "[Warning] ";
    case LogMsgType::kFatal:
      return "[Fatal] ";
    case LogMsgType::kInfo:
    default:
      return "[Info] ";
  }
}

void AppendLog(LogMsgType type, const std::string& text) {
  if (App().log == nullptr) {
    return;
  }

  int length = GetWindowTextLengthW(App().log);
  if (length > 2000000) {
    SetWindowTextW(App().log, L"");
    length = 0;
  }

  SYSTEMTIME now{};
  GetLocalTime(&now);
  const std::string line =
      text.empty()
          ? std::string("\r\n")
          : "[" +
                Format("%02u:%02u:%02u", now.wHour, now.wMinute, now.wSecond) +
                "] " + LogPrefix(type) + text + "\r\n";
  const std::wstring wide = Utf8ToWide(line);

  SendMessageW(App().log, EM_SETREADONLY, FALSE, 0);
  SendMessageW(App().log, EM_SETSEL, static_cast<WPARAM>(length),
               static_cast<LPARAM>(length));
  SendMessageW(App().log, EM_REPLACESEL, FALSE,
               reinterpret_cast<LPARAM>(wide.c_str()));
  SendMessageW(App().log, EM_SETREADONLY, TRUE, 0);
  SendMessageW(App().log, EM_SCROLLCARET, 0, 0);
}

void GuiLogSink(LogMsgType type, const std::string& message) {
  if (App().hwnd == nullptr) {
    return;
  }
  auto* entry = new LogEntry{type, message};
  if (!PostMessageW(App().hwnd, kMsgLog, 0, reinterpret_cast<LPARAM>(entry))) {
    delete entry;
  }
}

void GuiStatusSink(const std::string& text) {
  if (App().hwnd == nullptr) {
    return;
  }
  auto* copy = new std::string(text);
  if (!PostMessageW(App().hwnd, kMsgStatus, 0,
                    reinterpret_cast<LPARAM>(copy))) {
    delete copy;
  }
}

int SelectedCommand() {
  const int selection =
      static_cast<int>(SendMessageW(App().command, CB_GETCURSEL, 0, 0));
  if (selection < 0) {
    return -1;
  }
  return static_cast<int>(
      SendMessageW(App().command, CB_GETITEMDATA, selection, 0));
}

struct TargetFlags {
  std::wstring path;
  uint16_t machine = 0;
  bool is_dll = false;
  bool valid = false;
};

TargetFlags& CachedTargetFlags() {
  static TargetFlags* flags = new TargetFlags;
  return *flags;
}

std::wstring& LoggedTarget() {
  static std::wstring* target = new std::wstring;
  return *target;
}

// Reads the target PE flags once per path. UpdateCommandUi is called for
// every EN_CHANGE, so without the cache (and the debounce timer) a network
// path could stall the UI.
const TargetFlags& CurrentTargetFlags() {
  const std::wstring target = GetText(App().target);
  if (target == CachedTargetFlags().path) {
    return CachedTargetFlags();
  }

  CachedTargetFlags() = TargetFlags{};
  CachedTargetFlags().path = target;
  if (target.empty() || !FileExists(target)) {
    return CachedTargetFlags();
  }

  try {
    const PEFlags flags = ReadPEFlags(target);
    CachedTargetFlags().machine = flags.machine;
    CachedTargetFlags().is_dll = flags.is_dll;
    CachedTargetFlags().valid = true;
  } catch (...) {
  }
  return CachedTargetFlags();
}

void MaybeLogTargetInfo() {
  const std::wstring target = GetText(App().target);
  if (target.empty()) {
    LoggedTarget().clear();
    return;
  }
  if (target == LoggedTarget()) {
    return;
  }

  const TargetFlags& flags = CurrentTargetFlags();
  if (flags.path != target || !flags.valid) {
    return;
  }

  LoggedTarget() = target;
  LogF(kLogGood, "Opened target: %s", WideToUtf8(target).c_str());
  try {
    EmitPEInfo(target, [](const std::string& line) { Log(kLogInfo, line); });
  } catch (const std::exception& error) {
    LogF(kLogWarning, "Could not read the target PE info: %s", error.what());
  }
}

void UpdateAdvancedMenu() {
  if (App().advanced_menu == nullptr) {
    return;
  }
  CheckMenuItem(
      App().advanced_menu, kMenuAdvDataSections,
      MF_BYCOMMAND | (App().create_data_sections ? MF_CHECKED : MF_UNCHECKED));
  CheckMenuItem(
      App().advanced_menu, kMenuAdvNoScylla,
      MF_BYCOMMAND | (App().disable_scylla ? MF_CHECKED : MF_UNCHECKED));
  CheckMenuItem(
      App().advanced_menu, kMenuAdvFixRelocs,
      MF_BYCOMMAND | (App().fix_relocations ? MF_CHECKED : MF_UNCHECKED));
}

void EnableAdvancedItem(HMENU menu, UINT id, bool enabled) {
  if (menu == nullptr) {
    return;
  }
  EnableMenuItem(menu, id, MF_BYCOMMAND | (enabled ? MF_ENABLED : MF_GRAYED));
}

void UpdateCommandUi() {
  const int selection = SelectedCommand();
  const bool unpack = selection == static_cast<int>(Command::kUnpack);
  const bool shrink = selection == static_cast<int>(Command::kShrink);
  const bool dump_code = selection == static_cast<int>(Command::kDumpCode);
  const bool enabled = !App().running;
  const TargetFlags& target = CurrentTargetFlags();
  const bool dll_target = (unpack || shrink) && target.is_dll;
  const bool can_create_data = target.machine == IMAGE_FILE_MACHINE_I386;

  EnableAdvancedItem(App().advanced_menu, kMenuAdvDataSections,
                     enabled && unpack && can_create_data);
  EnableAdvancedItem(App().advanced_menu, kMenuAdvNoScylla, enabled && unpack);
  EnableAdvancedItem(App().advanced_menu, kMenuAdvFixRelocs,
                     enabled && dll_target);
  UpdateAdvancedMenu();

  EnableWindow(App().pid_label, enabled && dump_code);
  EnableWindow(App().pid, enabled && dump_code);
  EnableWindow(App().cancel, !enabled && App().cancel_event != nullptr);

  MaybeLogTargetInfo();
}

void SetRunning(bool running) {
  App().running = running;

  EnableWindow(App().target, !running);
  EnableWindow(App().browse, !running);
  EnableWindow(App().command, !running);
  EnableWindow(App().start, !running);
  EnableWindow(App().cancel, running && App().cancel_event != nullptr);

  if (!running) {
    UpdateCommandUi();
  } else {
    EnableAdvancedItem(App().advanced_menu, kMenuAdvDataSections, false);
    EnableAdvancedItem(App().advanced_menu, kMenuAdvNoScylla, false);
    EnableAdvancedItem(App().advanced_menu, kMenuAdvFixRelocs, false);
    EnableWindow(App().pid_label, FALSE);
    EnableWindow(App().pid, FALSE);
  }
}

void BrowseForTarget() {
  if (App().running) {
    return;
  }

  wchar_t file[32768]{};
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = App().hwnd;
  dialog.lpstrFilter =
      L"Executables (*.exe;*.dll)\0*.exe;*.dll\0All files (*.*)\0*.*\0";
  dialog.lpstrFile = file;
  dialog.nMaxFile = static_cast<DWORD>(_countof(file));
  dialog.lpstrDefExt = L"exe";
  dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;

  if (GetOpenFileNameW(&dialog)) {
    LoggedTarget().clear();
    SetWindowTextW(App().target, file);
    UpdateCommandUi();
  }
}

const wchar_t* CommandName(Command command) {
  switch (command) {
    case Command::kShrink:
      return L"shrink";
    case Command::kMkData:
      return L"mkdata";
    case Command::kDumpCode:
      return L"dumpcode";
    case Command::kInfo:
      return L"info";
    case Command::kUnpack:
    default:
      return L"unpack";
  }
}

bool ReadJob(Job* job, std::wstring* error) {
  const int selection = SelectedCommand();
  if (selection < 0) {
    *error = L"Select a command.";
    return false;
  }

  job->command = static_cast<Command>(selection);
  job->target = GetText(App().target);
  job->create_data_sections = App().create_data_sections;
  job->use_scylla_hide = !App().disable_scylla;
  job->fix_relocations = App().fix_relocations;
  job->pid = 0;

  if (job->target.empty()) {
    *error = L"Select a target file.";
    return false;
  }
  if (!FileExists(job->target)) {
    *error = L"Target file not found.";
    return false;
  }
  if (job->fix_relocations && !CurrentTargetFlags().is_dll) {
    job->fix_relocations = false;
    App().fix_relocations = false;
    UpdateAdvancedMenu();
  }
  if (job->create_data_sections &&
      CurrentTargetFlags().machine != IMAGE_FILE_MACHINE_I386) {
    // MkData only exists in the 32-bit build; the 64-bit debugger ignores it.
    job->create_data_sections = false;
    App().create_data_sections = false;
    UpdateAdvancedMenu();
  }

  return true;
}

#if defined(_WIN64)
bool LoadEmbeddedWorker(std::vector<uint8_t>* data) {
  const HRSRC resource =
      FindResourceW(nullptr, MAKEINTRESOURCEW(kWorkerResourceId),
                    MAKEINTRESOURCEW(kRtRcData));
  if (resource == nullptr) {
    return false;
  }
  const DWORD size = SizeofResource(nullptr, resource);
  const HGLOBAL handle = LoadResource(nullptr, resource);
  const void* bytes = handle != nullptr ? LockResource(handle) : nullptr;
  if (bytes == nullptr || size == 0) {
    return false;
  }
  data->assign(static_cast<const uint8_t*>(bytes),
               static_cast<const uint8_t*>(bytes) + size);
  return true;
}

bool WriteWorkerToTemp(const std::vector<uint8_t>& data, std::wstring* path) {
  wchar_t temp_dir[MAX_PATH]{};
  if (GetTempPathW(_countof(temp_dir), temp_dir) == 0) {
    return false;
  }

  wchar_t temp_name[MAX_PATH]{};
  if (GetTempFileNameW(temp_dir, L"mm", 0, temp_name) == 0) {
    return false;
  }

  std::wstring exe_path = temp_name;
  exe_path += L".exe";
  if (!MoveFileExW(temp_name, exe_path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    DeleteFileW(temp_name);
    return false;
  }

  HANDLE file = CreateFileW(exe_path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    DeleteFileW(exe_path.c_str());
    return false;
  }

  DWORD written = 0;
  const BOOL ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()),
                            &written, nullptr);
  CloseHandle(file);
  if (!ok || written != data.size()) {
    DeleteFileW(exe_path.c_str());
    return false;
  }

  *path = exe_path;
  return true;
}

bool RunWorkerJob(const Job& job) {
  std::vector<uint8_t> worker;
  if (!LoadEmbeddedWorker(&worker)) {
    Log(kLogFatal,
        "The embedded 32-bit worker is missing. Rebuild with "
        "-DMAGICMIDA_32BIT_WORKER=<path-to-32-bit-magicmida.exe>.");
    return false;
  }

  std::wstring worker_path;
  if (!WriteWorkerToTemp(worker, &worker_path)) {
    Log(kLogFatal, "Could not extract the embedded 32-bit worker.");
    return false;
  }

  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;

  HANDLE read_pipe = nullptr;
  HANDLE write_pipe = nullptr;
  if (!CreatePipe(&read_pipe, &write_pipe, &security, 0)) {
    DeleteFileW(worker_path.c_str());
    LogF(kLogFatal, "Could not create worker pipe (error %lu).",
         GetLastError());
    return false;
  }
  SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

  HANDLE nul =
      CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                  &security, OPEN_EXISTING, 0, nullptr);
  if (nul == INVALID_HANDLE_VALUE) {
    CloseHandle(read_pipe);
    CloseHandle(write_pipe);
    DeleteFileW(worker_path.c_str());
    Log(kLogFatal, "Could not open NUL for the 32-bit worker.");
    return false;
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = nul;
  startup.hStdOutput = write_pipe;
  startup.hStdError = write_pipe;

  std::wstring command_line =
      L"\"" + worker_path + L"\" --worker " +
      std::to_wstring(static_cast<int>(job.command)) + L" " +
      std::to_wstring(job.pid) + L" " +
      (job.create_data_sections ? L"1" : L"0") + L" " +
      (job.use_scylla_hide ? L"1" : L"0") + L" " +
      (job.fix_relocations ? L"1" : L"0") + L" \"" +
      (App().cancel_event_name.empty() ? L"-" : App().cancel_event_name) +
      L"\" \"" + job.target + L"\"";

  PROCESS_INFORMATION process{};
  const BOOL created = CreateProcessW(worker_path.c_str(), command_line.data(),
                                      nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                      nullptr, nullptr, &startup, &process);
  const DWORD create_error = GetLastError();
  CloseHandle(write_pipe);
  CloseHandle(nul);

  if (!created) {
    CloseHandle(read_pipe);
    DeleteFileW(worker_path.c_str());
    LogF(kLogFatal, "Could not start the 32-bit worker (error %lu).",
         create_error);
    return false;
  }

  std::string buffer;
  char chunk[4096];
  DWORD read = 0;
  while (ReadFile(read_pipe, chunk, sizeof(chunk), &read, nullptr) &&
         read > 0) {
    buffer.append(chunk, read);
    size_t newline = 0;
    while ((newline = buffer.find('\n')) != std::string::npos) {
      std::string line = buffer.substr(0, newline);
      buffer.erase(0, newline + 1);
      if (line.empty()) {
        continue;
      }
      if (line[0] == 'S') {
        ReportStatus(line.substr(1));
        continue;
      }
      LogMsgType type = kLogInfo;
      switch (line[0]) {
        case 'G':
          type = kLogGood;
          break;
        case 'W':
          type = kLogWarning;
          break;
        case 'F':
          type = kLogFatal;
          break;
        default:
          break;
      }
      Log(type, line.substr(1));
    }
  }
  if (!buffer.empty()) {
    Log(kLogInfo, buffer);
  }

  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exit_code = 1;
  GetExitCodeProcess(process.hProcess, &exit_code);
  if (exit_code != 0) {
    LogF(kLogWarning, "The 32-bit worker exited with code %lu.", exit_code);
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(read_pipe);
  DeleteFileW(worker_path.c_str());
  return exit_code == 0;
}
#else
bool RunWorkerJob(const Job& job) {
  (void)job;
  Log(kLogFatal,
      "32-bit worker dispatch is only available in the 64-bit build.");
  return false;
}
#endif

bool PrepareOutputFile(const std::wstring& target) {
  const std::wstring output = MakeUnpackedFileName(target);
  if (FileExists(output)) {
    LogF(kLogWarning,
         "The output file already exists and will be overwritten: %s",
         WideToUtf8(output).c_str());
  }

  // Fail before starting the debugger when the dump cannot be written (for
  // example, it is loaded in another process or read-only).
  HANDLE probe = CreateFileW(output.c_str(), GENERIC_WRITE, 0, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (probe == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND) {
      LogF(kLogFatal, "The output file is not writable: %s (error %lu)",
           WideToUtf8(output).c_str(), error);
      return false;
    }
    return true;
  }
  CloseHandle(probe);
  return true;
}

void NormalizeOutputLayout(const std::wstring& file_name) {
  try {
    NormalizePEFile(file_name);
  } catch (const std::exception& error) {
    LogF(kLogWarning, "PE layout normalization failed: %s", error.what());
  }
}

bool ExecuteJob(const Job& job) {
  if (App().cancel_event != nullptr) {
    SetCancellationEvent(App().cancel_event);
  }

  if (job.command == Command::kUnpack && !PrepareOutputFile(job.target)) {
    return false;
  }

  if (job.use_worker) {
    return RunWorkerJob(job);
  }

  bool success = false;
  try {
    switch (job.command) {
      case Command::kUnpack: {
#if defined(_WIN64)
        ThemidaDebugger64 debugger(job.target, L"", job.create_data_sections,
                                   job.use_scylla_hide, job.fix_relocations);
#else
        ThemidaDebugger debugger(job.target, L"", job.create_data_sections,
                                 job.use_scylla_hide, job.fix_relocations);
#endif
        debugger.Run();
        success = debugger.Succeeded();
        if (success) {
          const std::wstring output = MakeUnpackedFileName(job.target);
          if (FileExists(output)) {
            NormalizeOutputLayout(output);
          } else {
            LogF(kLogWarning, "Normalization skipped: output not found: %s",
                 WideToUtf8(output).c_str());
          }
        }
        break;
      }
      case Command::kShrink: {
        const std::wstring backup = job.target + L".bak";
        if (!CopyFileW(job.target.c_str(), backup.c_str(), TRUE)) {
          const DWORD error = GetLastError();
          if (error == ERROR_FILE_EXISTS) {
            LogF(kLogInfo, "Shrink backup already exists: %s",
                 WideToUtf8(backup).c_str());
          } else {
            LogF(kLogWarning, "Could not create shrink backup: %s (error %lu)",
                 WideToUtf8(backup).c_str(), error);
          }
        } else {
          LogF(kLogInfo, "Shrink backup written to: %s",
               WideToUtf8(backup).c_str());
        }

        Patcher patcher(job.target);
        patcher.ProcessShrink();
        if (job.fix_relocations) {
          try {
            FixDllRelocations(job.target, 0);
          } catch (const std::exception& error) {
            LogF(kLogWarning, "Relocation fix failed: %s", error.what());
          }
        }
        NormalizeOutputLayout(job.target);
        success = true;
        break;
      }
      case Command::kMkData: {
        Patcher patcher(job.target);
        success = patcher.ProcessMkData();
        if (success) {
          NormalizeOutputLayout(job.target);
        }
        break;
      }
      case Command::kDumpCode: {
        if (!EnableDebugPrivilege()) {
          Log(kLogInfo,
              "Could not enable SeDebugPrivilege (continuing anyway).");
        }
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, job.pid);
        if (process == nullptr) {
          throw std::runtime_error(Format("OpenProcess(%lu) failed (error %lu)",
                                          job.pid, GetLastError()));
        }
        try {
          Patcher patcher(job.target);
          patcher.DumpProcessCode(process);
          success = true;
        } catch (...) {
          CloseHandle(process);
          throw;
        }
        CloseHandle(process);
        break;
      }
      case Command::kInfo: {
        EmitPEInfo(job.target,
                   [](const std::string& line) { Log(kLogInfo, line); });
        success = true;
        break;
      }
    }
  } catch (const std::exception& error) {
    LogF(kLogFatal, "%s", error.what());
    success = false;
  } catch (...) {
    Log(kLogFatal, "Unknown error.");
    success = false;
  }

  return success;
}

DWORD WINAPI RunJobThread(LPVOID parameter) {
  Job* job = static_cast<Job*>(parameter);
  const bool success = ExecuteJob(*job);
  delete job;
  if (App().hwnd != nullptr) {
    PostMessageW(App().hwnd, kMsgDone, success ? 1 : 0, 0);
  }
  return 0;
}

bool ResolveJob(Job* job, uint16_t* machine, std::wstring* error) {
  uint16_t detected = 0;
  try {
    detected = ReadPEMachine(job->target);
  } catch (const std::exception& exception) {
    *error = L"Could not read the target PE header: ";
    *error += Utf8ToWide(exception.what());
    return false;
  }
  *machine = detected;

#if defined(_WIN64)
  if (detected == IMAGE_FILE_MACHINE_I386) {
    // A 32-bit target is unpacked by the embedded 32-bit worker.
    job->use_worker = true;
  } else if (detected == IMAGE_FILE_MACHINE_AMD64) {
    job->use_worker = false;
    if (job->command == Command::kMkData ||
        job->command == Command::kDumpCode) {
      *error = L"MkData and Dump code are only available for 32-bit targets.";
      return false;
    }
  } else {
    *error = L"Unsupported target architecture.";
    return false;
  }
#else
  if (detected != IMAGE_FILE_MACHINE_I386) {
    *error = L"This 32-bit build can only unpack 32-bit targets.";
    return false;
  }
#endif
  return true;
}

void StartJob() {
  if (App().running) {
    return;
  }

  Job job;
  std::wstring error;
  if (!ReadJob(&job, &error)) {
    MessageBoxW(App().hwnd, error.c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
    return;
  }

  uint16_t machine = 0;
  if (!ResolveJob(&job, &machine, &error)) {
    MessageBoxW(App().hwnd, error.c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
    return;
  }

  MaybeLogTargetInfo();

  if (job.command == Command::kDumpCode) {
    const std::wstring text = GetText(App().pid);
    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(text.c_str(), &end, 10);
    if (value == 0 || end == text.c_str() || *end != L'\0') {
      MessageBoxW(App().hwnd, L"Enter a valid process ID.", kWindowTitle,
                  MB_OK | MB_ICONWARNING);
      return;
    }
    job.pid = static_cast<DWORD>(value);
  }

  if (job.command == Command::kUnpack) {
    const std::wstring output = MakeUnpackedFileName(job.target);
    if (FileExists(output)) {
      const std::wstring text = L"The output file already exists:\n\n" +
                                output + L"\n\nOverwrite it?";
      if (MessageBoxW(App().hwnd, text.c_str(), kWindowTitle,
                      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
        return;
      }
    }
  }

  static unsigned int cancel_counter = 0;
  if (App().cancel_event != nullptr) {
    CloseHandle(App().cancel_event);
    App().cancel_event = nullptr;
  }
  App().cancel_event_name = L"Local\\MagicmidaCancel-" +
                            std::to_wstring(GetCurrentProcessId()) + L"-" +
                            std::to_wstring(GetTickCount64()) + L"-" +
                            std::to_wstring(++cancel_counter);
  App().cancel_event =
      CreateEventW(nullptr, TRUE, FALSE, App().cancel_event_name.c_str());
  if (App().cancel_event == nullptr) {
    LogF(kLogWarning, "Could not create the cancellation event (error %lu).",
         GetLastError());
    App().cancel_event_name.clear();
  }

  PEFlags flags;
  try {
    flags = ReadPEFlags(job.target);
  } catch (...) {
  }

  std::wstring status = L"Running: ";
  status += (machine == IMAGE_FILE_MACHINE_I386) ? L"i386" : L"amd64";
  status += flags.is_dll ? L" DLL " : L" EXE ";
  status += CommandName(job.command);

  LogF(kLogInfo, "Starting %s: %s",
       WideToUtf8(CommandName(job.command)).c_str(),
       WideToUtf8(job.target).c_str());
  SetRunning(true);
  SetStatus(status.c_str());

  auto* thread_job = new Job(job);
  HANDLE thread =
      CreateThread(nullptr, 0, RunJobThread, thread_job, 0, nullptr);
  if (thread == nullptr) {
    delete thread_job;
    if (App().cancel_event != nullptr) {
      CloseHandle(App().cancel_event);
      App().cancel_event = nullptr;
    }
    App().cancel_event_name.clear();
    SetCancellationEvent(nullptr);
    SetRunning(false);
    SetStatus(L"Failed to start.");
    LogF(kLogFatal, "Could not start worker thread (error %lu)",
         GetLastError());
    return;
  }
  App().worker = thread;
}

HWND CreateChild(const wchar_t* class_name, const wchar_t* text, DWORD style,
                 DWORD ex_style, int id) {
  return CreateWindowExW(ex_style, class_name, text,
                         WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, App().hwnd,
                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                         App().instance, nullptr);
}

void CreateControls(HWND hwnd) {
  App().hwnd = hwnd;
  App().target_label =
      CreateChild(L"STATIC", L"Target:", SS_LEFT, 0, kTargetLabel);
  App().target = CreateChild(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP,
                             WS_EX_CLIENTEDGE, kTarget);
  App().browse = CreateChild(L"BUTTON", L"Browse...",
                             BS_PUSHBUTTON | WS_TABSTOP, 0, kBrowse);
  App().command_label =
      CreateChild(L"STATIC", L"Action:", SS_LEFT, 0, kCommandLabel);
  App().command =
      CreateChild(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,
                  0, kCommand);
  App().pid_label = CreateChild(L"STATIC", L"PID:", SS_LEFT, 0, kPidLabel);
  App().pid = CreateChild(L"EDIT", L"0", ES_NUMBER | WS_TABSTOP,
                          WS_EX_CLIENTEDGE, kPid);
  App().start = CreateChild(L"BUTTON", L"Start", BS_DEFPUSHBUTTON | WS_TABSTOP,
                            0, kStart);
  App().cancel =
      CreateChild(L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, 0, kCancel);
  App().log = CreateChild(
      L"EDIT", L"", WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
      WS_EX_CLIENTEDGE, kLog);
  App().status = CreateChild(L"STATIC", L"Ready.",
                             SS_LEFT | SS_SUNKEN | SS_CENTERIMAGE, 0, kStatus);

  const auto add_command = [](Command command, const wchar_t* text) {
    const LRESULT index = SendMessageW(App().command, CB_ADDSTRING, 0,
                                       reinterpret_cast<LPARAM>(text));
    if (index != CB_ERR) {
      SendMessageW(App().command, CB_SETITEMDATA, static_cast<WPARAM>(index),
                   static_cast<LPARAM>(command));
    }
  };
  add_command(Command::kUnpack, L"Unpack");
  add_command(Command::kShrink, L"Shrink");
  add_command(Command::kMkData, L"Make data sections");
  add_command(Command::kDumpCode, L"Dump code");
  SendMessageW(App().command, CB_SETCURSEL, 0, 0);

  // Windows 2000-style UI font.  MS Sans Serif is the classic Win32 dialog
  // font; scaling keeps it readable on high-DPI displays.
  App().ui_font = CreateFontW(
      -MulDiv(8, DpiScale(), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
      DEFAULT_PITCH | FF_SWISS, L"MS Sans Serif");
  if (App().ui_font == nullptr) {
    App().ui_font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  }

  App().log_font = CreateFontW(
      -MulDiv(9, DpiScale(), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
      FIXED_PITCH | FF_MODERN, L"Courier New");
  if (App().log_font == nullptr) {
    App().log_font = App().ui_font;
  }

  const HWND normal_font_controls[] = {
      App().target_label, App().target,    App().browse, App().command_label,
      App().command,      App().pid_label, App().pid,    App().start,
      App().cancel,       App().status,
  };
  for (HWND control : normal_font_controls) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(App().ui_font),
                 TRUE);
  }
  SendMessageW(App().log, WM_SETFONT, reinterpret_cast<WPARAM>(App().log_font),
               TRUE);

  DragAcceptFiles(hwnd, TRUE);
  UpdateCommandUi();
}

void Layout(HWND hwnd) {
  RECT client{};
  GetClientRect(hwnd, &client);
  if (client.right <= 0 || client.bottom <= 0) {
    return;
  }

  const int margin = Dip(8);
  const int row_height = Dip(22);
  const int gap = Dip(6);
  const int label_height = Dip(18);
  const int width = client.right - 2 * margin;

  const int target_label_width = Dip(44);
  const int browse_width = Dip(60);
  const int command_label_width = Dip(52);
  const int command_width = Dip(140);
  const int pid_label_width = Dip(30);
  const int pid_edit_width = Dip(48);
  const int start_width = Dip(72);
  const int cancel_width = Dip(72);

  int y = margin;
  MoveWindow(App().target_label, margin, y + Dip(2), target_label_width,
             label_height, TRUE);
  MoveWindow(App().target, margin + target_label_width + Dip(4), y,
             width - target_label_width - Dip(4) - browse_width - Dip(6),
             row_height, TRUE);
  MoveWindow(App().browse, margin + width - browse_width, y, browse_width,
             row_height, TRUE);

  y += row_height + gap;
  int x = margin;
  MoveWindow(App().command_label, x, y + Dip(2), command_label_width,
             label_height, TRUE);
  x += command_label_width + Dip(4);
  MoveWindow(App().command, x, y, command_width, Dip(160), TRUE);
  x += command_width + Dip(8);
  MoveWindow(App().pid_label, x, y + Dip(2), pid_label_width, label_height,
             TRUE);
  x += pid_label_width + Dip(4);
  MoveWindow(App().pid, x, y, pid_edit_width, row_height, TRUE);
  MoveWindow(App().cancel, margin + width - start_width - Dip(6) - cancel_width,
             y, cancel_width, row_height, TRUE);
  MoveWindow(App().start, margin + width - start_width, y, start_width,
             row_height, TRUE);

  y += row_height + gap;
  const int status_height = Dip(18);
  const int status_y = client.bottom - margin - status_height;
  MoveWindow(App().status, margin, status_y, width, status_height, TRUE);

  int log_height = status_y - gap - y;
  if (log_height < Dip(80)) {
    log_height = Dip(80);
  }
  MoveWindow(App().log, margin, y, width, log_height, TRUE);
}

void CopyLog() {
  if (App().log == nullptr) {
    return;
  }

  std::wstring text;
  DWORD start = 0;
  DWORD end = 0;
  SendMessageW(App().log, EM_GETSEL, reinterpret_cast<WPARAM>(&start),
               reinterpret_cast<LPARAM>(&end));
  if (end > start) {
    text.resize(static_cast<size_t>(end - start) + 1);
    const LRESULT copied = SendMessageW(App().log, EM_GETSELTEXT, 0,
                                        reinterpret_cast<LPARAM>(text.data()));
    text.resize(copied > 0 ? static_cast<size_t>(copied) : 0);
  } else {
    const int length = GetWindowTextLengthW(App().log);
    if (length <= 0) {
      return;
    }
    text.resize(static_cast<size_t>(length) + 1);
    GetWindowTextW(App().log, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
  }

  if (text.empty()) {
    return;
  }

  if (!OpenClipboard(App().hwnd)) {
    return;
  }
  EmptyClipboard();
  const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
  HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
  if (memory != nullptr) {
    void* destination = GlobalLock(memory);
    if (destination != nullptr) {
      std::memcpy(destination, text.c_str(), bytes);
      GlobalUnlock(memory);
      if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr) {
        GlobalFree(memory);
      }
    } else {
      GlobalFree(memory);
    }
  }
  CloseClipboard();
  SetStatus(L"Log copied.");
}

void SaveLog() {
  if (App().log == nullptr) {
    return;
  }

  wchar_t file[MAX_PATH]{};
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = App().hwnd;
  dialog.lpstrFilter = L"Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0";
  dialog.lpstrFile = file;
  dialog.nMaxFile = static_cast<DWORD>(_countof(file));
  dialog.lpstrDefExt = L"txt";
  dialog.lpstrTitle = L"Save log";
  dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
  if (!GetSaveFileNameW(&dialog)) {
    return;
  }

  const int length = GetWindowTextLengthW(App().log);
  std::wstring text(static_cast<size_t>(length) + 1, L'\0');
  if (length > 0) {
    GetWindowTextW(App().log, text.data(), length + 1);
  }
  text.resize(static_cast<size_t>(length));

  try {
    FileStream out(file, FileStream::Mode::kCreate);
    constexpr uint8_t kBom[] = {0xEF, 0xBB, 0xBF};
    out.Write(kBom, sizeof(kBom));
    const std::string utf8 = WideToUtf8(text);
    if (!utf8.empty()) {
      out.Write(utf8.data(), utf8.size());
    }
    SetStatus(L"Log saved.");
  } catch (const std::exception& error) {
    MessageBoxW(App().hwnd, Utf8ToWide(error.what()).c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
  }
}

void ShowAbout() {
  std::wstring text = L"Magicmida ";
  text += Utf8ToWide(MAGICMIDA_VERSION);
  text += L"\n\nScyllaHide ";
  text += Utf8ToWide(scyllahide::Version());
  text += L" (embedded)\n\nUnpacks Themida/WinLicense protected binaries.";
  MessageBoxW(App().hwnd, text.c_str(), L"About Magicmida",
              MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM w_param,
                         LPARAM l_param) {
  switch (message) {
    case WM_CREATE:
      CreateControls(hwnd);
      return 0;

    case WM_SIZE:
      Layout(hwnd);
      return 0;

    case WM_TIMER:
      if (w_param == kTargetTimerId) {
        KillTimer(hwnd, kTargetTimerId);
        UpdateCommandUi();
      }
      return 0;

    case WM_COMMAND: {
      const int id = LOWORD(w_param);
      const int notification = HIWORD(w_param);
      switch (id) {
        case kBrowse:
        case kMenuOpen:
          BrowseForTarget();
          return 0;
        case kStart:
          StartJob();
          return 0;
        case kCancel:
          if (App().running && App().cancel_event != nullptr) {
            SetEvent(App().cancel_event);
            EnableWindow(App().cancel, FALSE);
            SetStatus(L"Cancelling...");
          }
          return 0;
        case kCommand:
          if (notification == CBN_SELCHANGE) {
            UpdateCommandUi();
          }
          return 0;
        case kTarget:
          if (notification == EN_CHANGE) {
            // Debounce: reading the PE flags on every keystroke can stall on
            // slow (network) paths.
            SetTimer(hwnd, kTargetTimerId, 250, nullptr);
          }
          return 0;
        case kMenuClearLog:
          SetWindowTextW(App().log, L"");
          return 0;
        case kMenuSaveLog:
          SaveLog();
          return 0;
        case kMenuCopyLog:
          CopyLog();
          return 0;
        case kMenuExit:
          PostMessageW(hwnd, WM_CLOSE, 0, 0);
          return 0;
        case kMenuAbout:
          ShowAbout();
          return 0;
        case kMenuAdvDataSections:
          App().create_data_sections = !App().create_data_sections;
          UpdateAdvancedMenu();
          return 0;
        case kMenuAdvNoScylla:
          App().disable_scylla = !App().disable_scylla;
          UpdateAdvancedMenu();
          return 0;
        case kMenuAdvFixRelocs:
          App().fix_relocations = !App().fix_relocations;
          UpdateAdvancedMenu();
          return 0;
        default:
          break;
      }
      break;
    }

    case WM_DROPFILES: {
      if (App().running) {
        DragFinish(reinterpret_cast<HDROP>(w_param));
        return 0;
      }
      auto drop = reinterpret_cast<HDROP>(w_param);
      const UINT length = DragQueryFileW(drop, 0, nullptr, 0);
      if (length > 0) {
        std::wstring path(static_cast<size_t>(length) + 1, L'\0');
        DragQueryFileW(drop, 0, path.data(), length + 1);
        path.resize(length);
        LoggedTarget().clear();
        SetWindowTextW(App().target, path.c_str());
        UpdateCommandUi();
      }
      DragFinish(drop);
      return 0;
    }

    case kMsgLog: {
      auto* entry = reinterpret_cast<LogEntry*>(l_param);
      if (entry != nullptr) {
        AppendLog(entry->type, entry->text);
        delete entry;
      }
      return 0;
    }

    case kMsgStatus: {
      auto* text = reinterpret_cast<std::string*>(l_param);
      if (text != nullptr) {
        SetStatus(Utf8ToWide(*text).c_str());
        delete text;
      }
      return 0;
    }

    case kMsgDone: {
      if (App().worker != nullptr) {
        WaitForSingleObject(App().worker, INFINITE);
        CloseHandle(App().worker);
        App().worker = nullptr;
      }
      if (App().cancel_event != nullptr) {
        CloseHandle(App().cancel_event);
        App().cancel_event = nullptr;
      }
      App().cancel_event_name.clear();
      SetCancellationEvent(nullptr);
      SetRunning(false);
      SetStatus(w_param != 0 ? L"Completed successfully."
                             : L"Failed. See the log.");
      return 0;
    }

    case WM_CLOSE:
      if (App().running) {
        MessageBoxW(hwnd,
                    L"An operation is still running. Please wait for it to "
                    L"finish.",
                    kWindowTitle, MB_OK | MB_ICONWARNING);
        return 0;
      }
      DestroyWindow(hwnd);
      return 0;

    case WM_DESTROY:
      KillTimer(hwnd, kTargetTimerId);
      if (App().cancel_event != nullptr) {
        CloseHandle(App().cancel_event);
        App().cancel_event = nullptr;
      }
      if (App().worker != nullptr) {
        CloseHandle(App().worker);
        App().worker = nullptr;
      }
      if (App().accel != nullptr) {
        DestroyAcceleratorTable(App().accel);
        App().accel = nullptr;
      }
      if (App().log_font != nullptr && App().log_font != App().ui_font) {
        DeleteObject(App().log_font);
        App().log_font = nullptr;
      }
      if (App().ui_font != nullptr) {
        DeleteObject(App().ui_font);
        App().ui_font = nullptr;
      }
      DragAcceptFiles(hwnd, FALSE);
      PostQuitMessage(0);
      return 0;

    default:
      break;
  }

  return DefWindowProcW(hwnd, message, w_param, l_param);
}

char WorkerLogPrefix(LogMsgType type) {
  switch (type) {
    case LogMsgType::kGood:
      return 'G';
    case LogMsgType::kWarning:
      return 'W';
    case LogMsgType::kFatal:
      return 'F';
    case LogMsgType::kInfo:
    default:
      return 'I';
  }
}

void WorkerLogSink(LogMsgType type, const std::string& message) {
  std::string payload = message;
  for (char& c : payload) {
    if (c == '\r' || c == '\n') {
      c = ' ';
    }
  }

  std::string line;
  line.push_back(WorkerLogPrefix(type));
  line += payload;
  line.push_back('\n');

  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (output == nullptr || output == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD written = 0;
  WriteFile(output, line.data(), static_cast<DWORD>(line.size()), &written,
            nullptr);
}

void WorkerStatusSink(const std::string& text) {
  std::string line = "S";
  line += text;
  line.push_back('\n');

  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (output == nullptr || output == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD written = 0;
  WriteFile(output, line.data(), static_cast<DWORD>(line.size()), &written,
            nullptr);
}

void CliWrite(const std::string& text) {
  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (output == nullptr || output == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD written = 0;
  WriteFile(output, text.data(), static_cast<DWORD>(text.size()), &written,
            nullptr);
}

void CliLogSink(LogMsgType type, const std::string& message) {
  SYSTEMTIME now{};
  GetLocalTime(&now);
  CliWrite("[" + Format("%02u:%02u:%02u", now.wHour, now.wMinute, now.wSecond) +
           "] " + LogPrefix(type) + message + "\r\n");
}

void AttachCliConsole() {
  if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
    AllocConsole();
  }
  const HANDLE output =
      CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                  nullptr, OPEN_EXISTING, 0, nullptr);
  if (output != INVALID_HANDLE_VALUE) {
    SetStdHandle(STD_OUTPUT_HANDLE, output);
    SetStdHandle(STD_ERROR_HANDLE, output);
  }
  SetConsoleOutputCP(CP_UTF8);
}

void PrintUsage() {
  CliWrite(
      "Usage:\n"
      "  magicmida.exe                          Open the GUI\n"
      "  magicmida.exe <target>                 Open the GUI with a target\n"
      "  magicmida.exe --unpack [options] <target>\n"
      "  magicmida.exe --shrink [--fix-relocs] <target>\n"
      "  magicmida.exe --mkdata <target>\n"
      "  magicmida.exe --dumpcode --pid <pid> <target>\n"
      "  magicmida.exe --info <target>\n"
      "\n"
      "Options:\n"
      "  --fix-relocs      Rebuild DLL relocations (Unpack/Shrink)\n"
      "  --data-sections   Create .rdata/.data (Unpack, 32-bit targets)\n"
      "  --no-scylla       Disable the embedded ScyllaHide\n"
      "  --force           Overwrite an existing dump\n"
      "  --pid <pid>       Process ID for --dumpcode\n"
      "  --help, --version\n");
}

void PrintVersion() {
  CliWrite("Magicmida " MAGICMIDA_VERSION " (ScyllaHide " +
           std::string(scyllahide::Version()) + ")\n");
}

int RunCommandLine(int argument_count, wchar_t** arguments) {
  AttachCliConsole();

  Job job;
  bool command_set = false;
  bool force = false;

  for (int i = 1; i < argument_count; ++i) {
    const std::wstring argument = arguments[i];
    if (argument == L"--help" || argument == L"-h") {
      PrintUsage();
      return 0;
    }
    if (argument == L"--version") {
      PrintVersion();
      return 0;
    }
    if (argument == L"--unpack") {
      job.command = Command::kUnpack;
      command_set = true;
    } else if (argument == L"--shrink") {
      job.command = Command::kShrink;
      command_set = true;
    } else if (argument == L"--mkdata") {
      job.command = Command::kMkData;
      command_set = true;
    } else if (argument == L"--dumpcode") {
      job.command = Command::kDumpCode;
      command_set = true;
    } else if (argument == L"--info") {
      job.command = Command::kInfo;
      command_set = true;
    } else if (argument == L"--fix-relocs") {
      job.fix_relocations = true;
    } else if (argument == L"--data-sections") {
      job.create_data_sections = true;
    } else if (argument == L"--no-scylla") {
      job.use_scylla_hide = false;
    } else if (argument == L"--force") {
      force = true;
    } else if (argument == L"--pid") {
      if (i + 1 >= argument_count) {
        CliWrite("error: --pid needs a value\n");
        return 2;
      }
      const std::wstring value = arguments[++i];
      wchar_t* end = nullptr;
      const unsigned long parsed = wcstoul(value.c_str(), &end, 10);
      if (parsed == 0 || end == value.c_str() || *end != L'\0') {
        CliWrite("error: invalid PID\n");
        return 2;
      }
      job.pid = static_cast<DWORD>(parsed);
    } else if (!argument.empty() && argument[0] == L'-') {
      CliWrite("error: unknown option " + WideToUtf8(argument) + "\n");
      PrintUsage();
      return 2;
    } else if (job.target.empty()) {
      job.target = argument;
    } else {
      CliWrite("error: only one target is supported per invocation\n");
      return 2;
    }
  }

  if (!command_set || job.target.empty()) {
    PrintUsage();
    return 2;
  }
  if (job.command == Command::kDumpCode && job.pid == 0) {
    CliWrite("error: --dumpcode needs --pid\n");
    return 2;
  }

  SetLog(CliLogSink);
  SetStatusReporter(nullptr);
  SetCancellationEvent(nullptr);

  std::wstring error;
  uint16_t machine = 0;
  if (!ResolveJob(&job, &machine, &error)) {
    Log(kLogFatal, WideToUtf8(error));
    return 1;
  }

  PEFlags flags;
  try {
    flags = ReadPEFlags(job.target);
  } catch (...) {
  }

  if (job.fix_relocations && !flags.is_dll) {
    Log(kLogWarning, "--fix-relocs is only applied to DLL targets.");
    job.fix_relocations = false;
  }
  if (job.fix_relocations && job.command != Command::kUnpack &&
      job.command != Command::kShrink) {
    Log(kLogWarning, "--fix-relocs only applies to Unpack and Shrink.");
    job.fix_relocations = false;
  }
  if (job.create_data_sections && job.command != Command::kUnpack) {
    Log(kLogWarning, "--data-sections only applies to Unpack.");
    job.create_data_sections = false;
  }
  if (job.create_data_sections && machine != IMAGE_FILE_MACHINE_I386) {
    Log(kLogWarning, "--data-sections is only available for 32-bit targets.");
    job.create_data_sections = false;
  }

  if (job.command == Command::kUnpack) {
    const std::wstring output = MakeUnpackedFileName(job.target);
    if (FileExists(output) && !force) {
      LogF(kLogFatal,
           "The output file already exists: %s (use --force to overwrite).",
           WideToUtf8(output).c_str());
      return 1;
    }
  }

  return ExecuteJob(job) ? 0 : 1;
}

int RunWorkerMode(int argument_count, wchar_t** arguments) {
  if (argument_count < 9) {
    return 2;
  }

  const int command = _wtoi(arguments[2]);
  if (command < static_cast<int>(Command::kUnpack) ||
      command > static_cast<int>(Command::kInfo)) {
    return 2;
  }

  Job job;
  job.command = static_cast<Command>(command);
  job.pid = static_cast<DWORD>(wcstoul(arguments[3], nullptr, 10));
  job.create_data_sections = wcscmp(arguments[4], L"1") == 0;
  job.use_scylla_hide = wcscmp(arguments[5], L"0") != 0;
  job.fix_relocations = wcscmp(arguments[6], L"1") == 0;
  const std::wstring cancel_name = arguments[7];
  job.target = arguments[8];
  job.use_worker = false;

  HANDLE cancel_event = nullptr;
  if (!cancel_name.empty() && cancel_name != L"-") {
    cancel_event = OpenEventW(SYNCHRONIZE, FALSE, cancel_name.c_str());
    if (cancel_event == nullptr) {
      LogF(kLogWarning, "Could not open the cancellation event (error %lu).",
           GetLastError());
    }
  }

  SetCancellationEvent(cancel_event);
  SetStatusReporter(WorkerStatusSink);
  SetLog(WorkerLogSink);
  const bool success = ExecuteJob(job);
  SetStatusReporter(nullptr);
  SetCancellationEvent(nullptr);
  if (cancel_event != nullptr) {
    CloseHandle(cancel_event);
  }
  return success ? 0 : 1;
}

}  // namespace

extern "C" int WINAPI WinMain(HINSTANCE instance, HINSTANCE /*previous*/,
                              LPSTR /*cmdLine*/, int show_command) {
  int argument_count = 0;
  LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
  if (arguments != nullptr && argument_count >= 2 &&
      _wcsicmp(arguments[1], L"--worker") == 0) {
    const int result = RunWorkerMode(argument_count, arguments);
    LocalFree(arguments);
    return result;
  }

  if (arguments != nullptr && argument_count >= 2 && arguments[1][0] == L'-') {
    const int result = RunCommandLine(argument_count, arguments);
    LocalFree(arguments);
    return result;
  }

#if defined(MAGICMIDA_WORKER_ONLY)
  // The 32-bit build is an internal worker only.  It must never present a
  // user-facing GUI; the 64-bit application launches it with --worker.
  if (arguments != nullptr) {
    LocalFree(arguments);
  }
  return 1;
#endif

  SetProcessDPIAware();
  DisableVisualStyles();

  App().instance = instance;

  HDC screen = GetDC(nullptr);
  DpiScale() = screen != nullptr ? GetDeviceCaps(screen, LOGPIXELSY) : 96;
  if (screen != nullptr) {
    ReleaseDC(nullptr, screen);
  }

  HMENU menu = CreateMenu();
  HMENU file_menu = CreatePopupMenu();
  AppendMenuW(file_menu, MF_STRING, kMenuOpen, L"&Open...\tCtrl+O");
  AppendMenuW(file_menu, MF_STRING, kMenuClearLog, L"&Clear log");
  AppendMenuW(file_menu, MF_STRING, kMenuSaveLog, L"&Save log...\tCtrl+S");
  AppendMenuW(file_menu, MF_STRING, kMenuCopyLog, L"&Copy log");
  AppendMenuW(file_menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(file_menu, MF_STRING, kMenuExit, L"E&xit");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(file_menu), L"&File");

  HMENU advanced_menu = CreatePopupMenu();
  AppendMenuW(advanced_menu, MF_STRING, kMenuAdvDataSections,
              L"&Create data sections");
  AppendMenuW(advanced_menu, MF_STRING, kMenuAdvNoScylla,
              L"&Disable ScyllaHide");
  AppendMenuW(advanced_menu, MF_STRING, kMenuAdvFixRelocs,
              L"&Fix DLL relocations");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(advanced_menu),
              L"&Advanced");
  App().menu = menu;
  App().advanced_menu = advanced_menu;

  HMENU help_menu = CreatePopupMenu();
  AppendMenuW(help_menu, MF_STRING, kMenuAbout, L"&About");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(help_menu), L"&Help");

  WNDCLASSEXW window_class{};
  window_class.cbSize = sizeof(window_class);
  window_class.style = CS_HREDRAW | CS_VREDRAW;
  window_class.lpfnWndProc = WndProc;
  window_class.hInstance = instance;
  window_class.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
  window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
  window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
  window_class.lpszClassName = kWindowClass;
  window_class.hIconSm = window_class.hIcon;

  if (RegisterClassExW(&window_class) == 0) {
    return 1;
  }

  const int max_window_width = GetSystemMetrics(SM_CXSCREEN) - Dip(40);
  const int max_window_height = GetSystemMetrics(SM_CYSCREEN) - Dip(80);
  const int window_width = std::min(Dip(900), max_window_width);
  const int window_height = std::min(Dip(430), max_window_height);

  // Fixed-size classic window: no thick frame and no maximize box.
  HWND hwnd = CreateWindowExW(0, kWindowClass, kWindowTitle,
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
                                  WS_MINIMIZEBOX | WS_CLIPCHILDREN,
                              CW_USEDEFAULT, CW_USEDEFAULT, window_width,
                              window_height, nullptr, menu, instance, nullptr);
  if (hwnd == nullptr) {
    return 1;
  }

  if (arguments != nullptr) {
    if (argument_count >= 2 && arguments[1][0] != L'-') {
      SetWindowTextW(App().target, arguments[1]);
    }
    LocalFree(arguments);
    arguments = nullptr;
  }
  UpdateCommandUi();

  ACCEL accelerator[2]{};
  accelerator[0].fVirt = FVIRTKEY | FCONTROL;
  accelerator[0].key = 'O';
  accelerator[0].cmd = kMenuOpen;
  accelerator[1].fVirt = FVIRTKEY | FCONTROL;
  accelerator[1].key = 'S';
  accelerator[1].cmd = kMenuSaveLog;
  App().accel = CreateAcceleratorTableW(accelerator, 2);

  SetLog(GuiLogSink);
  SetStatusReporter(GuiStatusSink);
  LogF(kLogInfo, "Magicmida %s GUI ready. ScyllaHide %s embedded.",
       MAGICMIDA_VERSION, scyllahide::Version());

  ShowWindow(hwnd, show_command);
  UpdateWindow(hwnd);

  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    if (App().accel == nullptr ||
        !TranslateAcceleratorW(hwnd, App().accel, &message)) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
  }

  return static_cast<int>(message.wParam);
}
}  // namespace magicmida
