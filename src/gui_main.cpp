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

using namespace magicmida;

namespace {

constexpr wchar_t kWindowClass[] = L"MagicmidaGuiWindow";
constexpr wchar_t kWindowTitle[] = L"Magicmida";
constexpr WORD kWorkerResourceId = 103;
constexpr WORD kRtRcData = 10;
constexpr UINT_PTR kTargetTimerId = 1;

enum ControlId : int {
  IDC_TARGET_LABEL = 100,
  IDC_TARGET,
  IDC_BROWSE,
  IDC_COMMAND_LABEL,
  IDC_COMMAND,
  IDC_PID_LABEL,
  IDC_PID,
  IDC_START,
  IDC_CANCEL,
  IDC_LOG,
  IDC_STATUS,
};

enum MenuId : int {
  IDM_OPEN = 200,
  IDM_CLEAR_LOG,
  IDM_SAVE_LOG,
  IDM_COPY_LOG,
  IDM_EXIT,
  IDM_ABOUT,
  IDM_ADV_DATA_SECTIONS,
  IDM_ADV_NO_SCYLLA,
  IDM_ADV_FIX_RELOCS,
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
  HMENU advancedMenu = nullptr;
  HWND targetLabel = nullptr;
  HWND target = nullptr;
  HWND browse = nullptr;
  HWND commandLabel = nullptr;
  HWND command = nullptr;
  HWND pidLabel = nullptr;
  HWND pid = nullptr;
  HWND start = nullptr;
  HWND cancel = nullptr;
  HWND log = nullptr;
  HWND status = nullptr;
  bool createDataSections = false;
  bool disableScylla = false;
  bool fixRelocations = false;
  HANDLE cancelEvent = nullptr;
  std::wstring cancelEventName;
  HFONT uiFont = nullptr;
  HFONT logFont = nullptr;
  HACCEL accel = nullptr;
  HANDLE worker = nullptr;
  bool running = false;
};

AppState g_app;
int g_dpi = 96;

int Dip(int value) {
  return MulDiv(value, g_dpi, 96);
}

enum class Command {
  Unpack = 0,
  Shrink = 1,
  MkData = 2,
  DumpCode = 3,
  Info = 4,
};

struct Job {
  Command command = Command::Unpack;
  std::wstring target;
  bool createDataSections = false;
  bool useScyllaHide = true;
  bool fixRelocations = false;
  bool useWorker = false;
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
  using SetThemeAppPropertiesFn = void(WINAPI*)(DWORD);
  const auto setThemeAppProperties =
      reinterpret_cast<SetThemeAppPropertiesFn>(
          GetProcAddress(uxtheme, "SetThemeAppProperties"));
  if (setThemeAppProperties != nullptr) {
    setThemeAppProperties(0);
  }
}

void SetStatus(const wchar_t* text) {
  if (g_app.status != nullptr) {
    SetWindowTextW(g_app.status, text);
  }
}

const char* LogPrefix(LogMsgType type) {
  switch (type) {
    case LogMsgType::Good:
      return "[Good] ";
    case LogMsgType::Warning:
      return "[Warning] ";
    case LogMsgType::Fatal:
      return "[Fatal] ";
    case LogMsgType::Info:
    default:
      return "[Info] ";
  }
}

void AppendLog(LogMsgType type, const std::string& text) {
  if (g_app.log == nullptr) {
    return;
  }

  int length = GetWindowTextLengthW(g_app.log);
  if (length > 2000000) {
    SetWindowTextW(g_app.log, L"");
    length = 0;
  }

  SYSTEMTIME now{};
  GetLocalTime(&now);
  const std::string line =
      text.empty()
          ? std::string("\r\n")
          : "[" + Format("%02u:%02u:%02u", now.wHour, now.wMinute,
                         now.wSecond) +
                "] " + LogPrefix(type) + text + "\r\n";
  const std::wstring wide = Utf8ToWide(line);

  SendMessageW(g_app.log, EM_SETREADONLY, FALSE, 0);
  SendMessageW(g_app.log, EM_SETSEL, static_cast<WPARAM>(length),
               static_cast<LPARAM>(length));
  SendMessageW(g_app.log, EM_REPLACESEL, FALSE,
               reinterpret_cast<LPARAM>(wide.c_str()));
  SendMessageW(g_app.log, EM_SETREADONLY, TRUE, 0);
  SendMessageW(g_app.log, EM_SCROLLCARET, 0, 0);
}

void GuiLogSink(LogMsgType type, const std::string& message) {
  if (g_app.hwnd == nullptr) {
    return;
  }
  auto* entry = new LogEntry{type, message};
  if (!PostMessageW(g_app.hwnd, kMsgLog, 0,
                    reinterpret_cast<LPARAM>(entry))) {
    delete entry;
  }
}

void GuiStatusSink(const std::string& text) {
  if (g_app.hwnd == nullptr) {
    return;
  }
  auto* copy = new std::string(text);
  if (!PostMessageW(g_app.hwnd, kMsgStatus, 0,
                    reinterpret_cast<LPARAM>(copy))) {
    delete copy;
  }
}

int SelectedCommand() {
  const int selection = static_cast<int>(
      SendMessageW(g_app.command, CB_GETCURSEL, 0, 0));
  if (selection < 0) {
    return -1;
  }
  return static_cast<int>(
      SendMessageW(g_app.command, CB_GETITEMDATA, selection, 0));
}

struct TargetFlags {
  std::wstring path;
  uint16_t machine = 0;
  bool isDll = false;
  bool valid = false;
};

TargetFlags g_targetFlags;
std::wstring g_loggedTarget;

// Reads the target PE flags once per path. UpdateCommandUi is called for
// every EN_CHANGE, so without the cache (and the debounce timer) a network
// path could stall the UI.
const TargetFlags& CurrentTargetFlags() {
  const std::wstring target = GetText(g_app.target);
  if (target == g_targetFlags.path) {
    return g_targetFlags;
  }

  g_targetFlags = TargetFlags{};
  g_targetFlags.path = target;
  if (target.empty() || !FileExists(target)) {
    return g_targetFlags;
  }

  try {
    const PEFlags flags = ReadPEFlags(target);
    g_targetFlags.machine = flags.machine;
    g_targetFlags.isDll = flags.isDll;
    g_targetFlags.valid = true;
  } catch (...) {
  }
  return g_targetFlags;
}

void MaybeLogTargetInfo() {
  const std::wstring target = GetText(g_app.target);
  if (target.empty()) {
    g_loggedTarget.clear();
    return;
  }
  if (target == g_loggedTarget) {
    return;
  }

  const TargetFlags& flags = CurrentTargetFlags();
  if (flags.path != target || !flags.valid) {
    return;
  }

  g_loggedTarget = target;
  LogF(ltGood, "Opened target: %s", WideToUtf8(target).c_str());
  try {
    EmitPEInfo(target, [](const std::string& line) { Log(ltInfo, line); });
  } catch (const std::exception& error) {
    LogF(ltWarning, "Could not read the target PE info: %s", error.what());
  }
}

void UpdateAdvancedMenu() {
  if (g_app.advancedMenu == nullptr) {
    return;
  }
  CheckMenuItem(g_app.advancedMenu, IDM_ADV_DATA_SECTIONS,
                MF_BYCOMMAND | (g_app.createDataSections ? MF_CHECKED
                                                         : MF_UNCHECKED));
  CheckMenuItem(g_app.advancedMenu, IDM_ADV_NO_SCYLLA,
                MF_BYCOMMAND | (g_app.disableScylla ? MF_CHECKED
                                                    : MF_UNCHECKED));
  CheckMenuItem(g_app.advancedMenu, IDM_ADV_FIX_RELOCS,
                MF_BYCOMMAND | (g_app.fixRelocations ? MF_CHECKED
                                                     : MF_UNCHECKED));
}

void EnableAdvancedItem(HMENU menu, UINT id, bool enabled) {
  if (menu == nullptr) {
    return;
  }
  EnableMenuItem(menu, id,
                 MF_BYCOMMAND | (enabled ? MF_ENABLED : MF_GRAYED));
}

void UpdateCommandUi() {
  const int selection = SelectedCommand();
  const bool unpack = selection == static_cast<int>(Command::Unpack);
  const bool shrink = selection == static_cast<int>(Command::Shrink);
  const bool dumpCode = selection == static_cast<int>(Command::DumpCode);
  const bool enabled = !g_app.running;
  const TargetFlags& target = CurrentTargetFlags();
  const bool dllTarget = (unpack || shrink) && target.isDll;
  const bool canCreateData = target.machine == IMAGE_FILE_MACHINE_I386;

  EnableAdvancedItem(g_app.advancedMenu, IDM_ADV_DATA_SECTIONS,
                     enabled && unpack && canCreateData);
  EnableAdvancedItem(g_app.advancedMenu, IDM_ADV_NO_SCYLLA,
                     enabled && unpack);
  EnableAdvancedItem(g_app.advancedMenu, IDM_ADV_FIX_RELOCS,
                     enabled && dllTarget);
  UpdateAdvancedMenu();

  EnableWindow(g_app.pidLabel, enabled && dumpCode);
  EnableWindow(g_app.pid, enabled && dumpCode);
  EnableWindow(g_app.cancel, !enabled && g_app.cancelEvent != nullptr);

  MaybeLogTargetInfo();
}

void SetRunning(bool running) {
  g_app.running = running;

  EnableWindow(g_app.target, !running);
  EnableWindow(g_app.browse, !running);
  EnableWindow(g_app.command, !running);
  EnableWindow(g_app.start, !running);
  EnableWindow(g_app.cancel, running && g_app.cancelEvent != nullptr);

  if (!running) {
    UpdateCommandUi();
  } else {
    EnableAdvancedItem(g_app.advancedMenu, IDM_ADV_DATA_SECTIONS, false);
    EnableAdvancedItem(g_app.advancedMenu, IDM_ADV_NO_SCYLLA, false);
    EnableAdvancedItem(g_app.advancedMenu, IDM_ADV_FIX_RELOCS, false);
    EnableWindow(g_app.pidLabel, FALSE);
    EnableWindow(g_app.pid, FALSE);
  }
}

void BrowseForTarget() {
  if (g_app.running) {
    return;
  }

  wchar_t file[32768]{};
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = g_app.hwnd;
  dialog.lpstrFilter =
      L"Executables (*.exe;*.dll)\0*.exe;*.dll\0All files (*.*)\0*.*\0";
  dialog.lpstrFile = file;
  dialog.nMaxFile = static_cast<DWORD>(_countof(file));
  dialog.lpstrDefExt = L"exe";
  dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;

  if (GetOpenFileNameW(&dialog)) {
    g_loggedTarget.clear();
    SetWindowTextW(g_app.target, file);
    UpdateCommandUi();
  }
}

const wchar_t* CommandName(Command command) {
  switch (command) {
    case Command::Shrink:
      return L"shrink";
    case Command::MkData:
      return L"mkdata";
    case Command::DumpCode:
      return L"dumpcode";
    case Command::Info:
      return L"info";
    case Command::Unpack:
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
  job->target = GetText(g_app.target);
  job->createDataSections = g_app.createDataSections;
  job->useScyllaHide = !g_app.disableScylla;
  job->fixRelocations = g_app.fixRelocations;
  job->pid = 0;

  if (job->target.empty()) {
    *error = L"Select a target file.";
    return false;
  }
  if (!FileExists(job->target)) {
    *error = L"Target file not found.";
    return false;
  }
  if (job->fixRelocations && !CurrentTargetFlags().isDll) {
    job->fixRelocations = false;
    g_app.fixRelocations = false;
    UpdateAdvancedMenu();
  }
  if (job->createDataSections &&
      CurrentTargetFlags().machine != IMAGE_FILE_MACHINE_I386) {
    // MkData only exists in the 32-bit build; the 64-bit debugger ignores it.
    job->createDataSections = false;
    g_app.createDataSections = false;
    UpdateAdvancedMenu();
  }

  return true;
}

#if defined(_WIN64)
bool LoadEmbeddedWorker(std::vector<uint8_t>* data) {
  const HRSRC resource = FindResourceW(
      nullptr, MAKEINTRESOURCEW(kWorkerResourceId),
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
  wchar_t tempDir[MAX_PATH]{};
  if (GetTempPathW(_countof(tempDir), tempDir) == 0) {
    return false;
  }

  wchar_t tempName[MAX_PATH]{};
  if (GetTempFileNameW(tempDir, L"mm", 0, tempName) == 0) {
    return false;
  }

  std::wstring exePath = tempName;
  exePath += L".exe";
  if (!MoveFileExW(tempName, exePath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    DeleteFileW(tempName);
    return false;
  }

  HANDLE file = CreateFileW(exePath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    DeleteFileW(exePath.c_str());
    return false;
  }

  DWORD written = 0;
  const BOOL ok = WriteFile(file, data.data(),
                            static_cast<DWORD>(data.size()), &written, nullptr);
  CloseHandle(file);
  if (!ok || written != data.size()) {
    DeleteFileW(exePath.c_str());
    return false;
  }

  *path = exePath;
  return true;
}

bool RunWorkerJob(const Job& job) {
  std::vector<uint8_t> worker;
  if (!LoadEmbeddedWorker(&worker)) {
    Log(ltFatal,
        "The embedded 32-bit worker is missing. Rebuild with "
        "-DMAGICMIDA_32BIT_WORKER=<path-to-32-bit-magicmida.exe>.");
    return false;
  }

  std::wstring workerPath;
  if (!WriteWorkerToTemp(worker, &workerPath)) {
    Log(ltFatal, "Could not extract the embedded 32-bit worker.");
    return false;
  }

  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;

  HANDLE readPipe = nullptr;
  HANDLE writePipe = nullptr;
  if (!CreatePipe(&readPipe, &writePipe, &security, 0)) {
    DeleteFileW(workerPath.c_str());
    LogF(ltFatal, "Could not create worker pipe (error %lu).", GetLastError());
    return false;
  }
  SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

  HANDLE nul = CreateFileW(L"NUL", GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                           OPEN_EXISTING, 0, nullptr);
  if (nul == INVALID_HANDLE_VALUE) {
    CloseHandle(readPipe);
    CloseHandle(writePipe);
    DeleteFileW(workerPath.c_str());
    Log(ltFatal, "Could not open NUL for the 32-bit worker.");
    return false;
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = nul;
  startup.hStdOutput = writePipe;
  startup.hStdError = writePipe;

  std::wstring commandLine =
      L"\"" + workerPath + L"\" --worker " +
      std::to_wstring(static_cast<int>(job.command)) + L" " +
      std::to_wstring(job.pid) + L" " +
      (job.createDataSections ? L"1" : L"0") + L" " +
      (job.useScyllaHide ? L"1" : L"0") + L" " +
      (job.fixRelocations ? L"1" : L"0") + L" \"" +
      (g_app.cancelEventName.empty() ? L"-" : g_app.cancelEventName) +
      L"\" \"" + job.target + L"\"";

  PROCESS_INFORMATION process{};
  const BOOL created = CreateProcessW(
      workerPath.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  const DWORD createError = GetLastError();
  CloseHandle(writePipe);
  CloseHandle(nul);

  if (!created) {
    CloseHandle(readPipe);
    DeleteFileW(workerPath.c_str());
    LogF(ltFatal, "Could not start the 32-bit worker (error %lu).",
         createError);
    return false;
  }

  std::string buffer;
  char chunk[4096];
  DWORD read = 0;
  while (ReadFile(readPipe, chunk, sizeof(chunk), &read, nullptr) && read > 0) {
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
      LogMsgType type = ltInfo;
      switch (line[0]) {
        case 'G':
          type = ltGood;
          break;
        case 'W':
          type = ltWarning;
          break;
        case 'F':
          type = ltFatal;
          break;
        default:
          break;
      }
      Log(type, line.substr(1));
    }
  }
  if (!buffer.empty()) {
    Log(ltInfo, buffer);
  }

  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exitCode = 1;
  GetExitCodeProcess(process.hProcess, &exitCode);
  if (exitCode != 0) {
    LogF(ltWarning, "The 32-bit worker exited with code %lu.", exitCode);
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(readPipe);
  DeleteFileW(workerPath.c_str());
  return exitCode == 0;
}
#else
bool RunWorkerJob(const Job& job) {
  (void)job;
  Log(ltFatal,
      "32-bit worker dispatch is only available in the 64-bit build.");
  return false;
}
#endif

bool PrepareOutputFile(const std::wstring& target) {
  const std::wstring output = MakeUnpackedFileName(target);
  if (FileExists(output)) {
    LogF(ltWarning,
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
      LogF(ltFatal, "The output file is not writable: %s (error %lu)",
           WideToUtf8(output).c_str(), error);
      return false;
    }
    return true;
  }
  CloseHandle(probe);
  return true;
}

void NormalizeOutputLayout(const std::wstring& fileName) {
  try {
    NormalizePEFile(fileName);
  } catch (const std::exception& error) {
    LogF(ltWarning, "PE layout normalization failed: %s", error.what());
  }
}

bool ExecuteJob(const Job& job) {
  if (g_app.cancelEvent != nullptr) {
    SetCancellationEvent(g_app.cancelEvent);
  }

  if (job.command == Command::Unpack && !PrepareOutputFile(job.target)) {
    return false;
  }

  if (job.useWorker) {
    return RunWorkerJob(job);
  }

  bool success = false;
  try {
    switch (job.command) {
      case Command::Unpack: {
#if defined(_WIN64)
        ThemidaDebugger64 debugger(job.target, L"", job.createDataSections,
                                   job.useScyllaHide, job.fixRelocations);
#else
        ThemidaDebugger debugger(job.target, L"", job.createDataSections,
                                 job.useScyllaHide, job.fixRelocations);
#endif
        debugger.Run();
        success = debugger.Succeeded();
        if (success) {
          const std::wstring output = MakeUnpackedFileName(job.target);
          if (FileExists(output)) {
            NormalizeOutputLayout(output);
          } else {
            LogF(ltWarning, "Normalization skipped: output not found: %s",
                 WideToUtf8(output).c_str());
          }
        }
        break;
      }
      case Command::Shrink: {
        const std::wstring backup = job.target + L".bak";
        if (!CopyFileW(job.target.c_str(), backup.c_str(), TRUE)) {
          const DWORD error = GetLastError();
          if (error == ERROR_FILE_EXISTS) {
            LogF(ltInfo, "Shrink backup already exists: %s",
                 WideToUtf8(backup).c_str());
          } else {
            LogF(ltWarning, "Could not create shrink backup: %s (error %lu)",
                 WideToUtf8(backup).c_str(), error);
          }
        } else {
          LogF(ltInfo, "Shrink backup written to: %s",
               WideToUtf8(backup).c_str());
        }

        Patcher patcher(job.target);
        patcher.ProcessShrink();
        if (job.fixRelocations) {
          try {
            FixDllRelocations(job.target, 0);
          } catch (const std::exception& error) {
            LogF(ltWarning, "Relocation fix failed: %s", error.what());
          }
        }
        NormalizeOutputLayout(job.target);
        success = true;
        break;
      }
      case Command::MkData: {
        Patcher patcher(job.target);
        success = patcher.ProcessMkData();
        if (success) {
          NormalizeOutputLayout(job.target);
        }
        break;
      }
      case Command::DumpCode: {
        if (!EnableDebugPrivilege()) {
          Log(ltInfo,
              "Could not enable SeDebugPrivilege (continuing anyway).");
        }
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, job.pid);
        if (process == nullptr) {
          throw std::runtime_error(Format(
              "OpenProcess(%lu) failed (error %lu)", job.pid, GetLastError()));
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
      case Command::Info: {
        EmitPEInfo(job.target, [](const std::string& line) {
          Log(ltInfo, line);
        });
        success = true;
        break;
      }
    }
  } catch (const std::exception& error) {
    LogF(ltFatal, "%s", error.what());
    success = false;
  } catch (...) {
    Log(ltFatal, "Unknown error.");
    success = false;
  }

  return success;
}

DWORD WINAPI RunJobThread(LPVOID parameter) {
  Job* job = static_cast<Job*>(parameter);
  const bool success = ExecuteJob(*job);
  delete job;
  if (g_app.hwnd != nullptr) {
    PostMessageW(g_app.hwnd, kMsgDone, success ? 1 : 0, 0);
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
    job->useWorker = true;
  } else if (detected == IMAGE_FILE_MACHINE_AMD64) {
    job->useWorker = false;
    if (job->command == Command::MkData ||
        job->command == Command::DumpCode) {
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
  if (g_app.running) {
    return;
  }

  Job job;
  std::wstring error;
  if (!ReadJob(&job, &error)) {
    MessageBoxW(g_app.hwnd, error.c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
    return;
  }

  uint16_t machine = 0;
  if (!ResolveJob(&job, &machine, &error)) {
    MessageBoxW(g_app.hwnd, error.c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
    return;
  }

  MaybeLogTargetInfo();

  if (job.command == Command::DumpCode) {
    const std::wstring text = GetText(g_app.pid);
    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(text.c_str(), &end, 10);
    if (value == 0 || end == text.c_str() || *end != L'\0') {
      MessageBoxW(g_app.hwnd, L"Enter a valid process ID.", kWindowTitle,
                  MB_OK | MB_ICONWARNING);
      return;
    }
    job.pid = static_cast<DWORD>(value);
  }

  if (job.command == Command::Unpack) {
    const std::wstring output = MakeUnpackedFileName(job.target);
    if (FileExists(output)) {
      const std::wstring text =
          L"The output file already exists:\n\n" + output +
          L"\n\nOverwrite it?";
      if (MessageBoxW(g_app.hwnd, text.c_str(), kWindowTitle,
                      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
        return;
      }
    }
  }

  static unsigned int cancelCounter = 0;
  if (g_app.cancelEvent != nullptr) {
    CloseHandle(g_app.cancelEvent);
    g_app.cancelEvent = nullptr;
  }
  g_app.cancelEventName =
      L"Local\\MagicmidaCancel-" + std::to_wstring(GetCurrentProcessId()) +
      L"-" + std::to_wstring(GetTickCount64()) + L"-" +
      std::to_wstring(++cancelCounter);
  g_app.cancelEvent =
      CreateEventW(nullptr, TRUE, FALSE, g_app.cancelEventName.c_str());
  if (g_app.cancelEvent == nullptr) {
    LogF(ltWarning, "Could not create the cancellation event (error %lu).",
         GetLastError());
    g_app.cancelEventName.clear();
  }

  PEFlags flags;
  try {
    flags = ReadPEFlags(job.target);
  } catch (...) {
  }

  std::wstring status = L"Running: ";
  status += (machine == IMAGE_FILE_MACHINE_I386) ? L"i386" : L"amd64";
  status += flags.isDll ? L" DLL " : L" EXE ";
  status += CommandName(job.command);

  LogF(ltInfo, "Starting %s: %s", WideToUtf8(CommandName(job.command)).c_str(),
       WideToUtf8(job.target).c_str());
  SetRunning(true);
  SetStatus(status.c_str());

  auto* threadJob = new Job(job);
  HANDLE thread = CreateThread(nullptr, 0, RunJobThread, threadJob, 0, nullptr);
  if (thread == nullptr) {
    delete threadJob;
    if (g_app.cancelEvent != nullptr) {
      CloseHandle(g_app.cancelEvent);
      g_app.cancelEvent = nullptr;
    }
    g_app.cancelEventName.clear();
    SetCancellationEvent(nullptr);
    SetRunning(false);
    SetStatus(L"Failed to start.");
    LogF(ltFatal, "Could not start worker thread (error %lu)", GetLastError());
    return;
  }
  g_app.worker = thread;
}

HWND CreateChild(const wchar_t* className, const wchar_t* text, DWORD style,
                 DWORD exStyle, int id) {
  return CreateWindowExW(
      exStyle, className, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0,
      g_app.hwnd,
      reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_app.instance,
      nullptr);
}

void CreateControls(HWND hwnd) {
  g_app.hwnd = hwnd;
  g_app.targetLabel =
      CreateChild(L"STATIC", L"Target:", SS_LEFT, 0, IDC_TARGET_LABEL);
  g_app.target = CreateChild(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP,
                             WS_EX_CLIENTEDGE, IDC_TARGET);
  g_app.browse =
      CreateChild(L"BUTTON", L"Browse...", BS_PUSHBUTTON | WS_TABSTOP, 0,
                  IDC_BROWSE);
  g_app.commandLabel =
      CreateChild(L"STATIC", L"Action:", SS_LEFT, 0, IDC_COMMAND_LABEL);
  g_app.command = CreateChild(L"COMBOBOX", L"",
                              CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 0,
                              IDC_COMMAND);
  g_app.pidLabel =
      CreateChild(L"STATIC", L"PID:", SS_LEFT, 0, IDC_PID_LABEL);
  g_app.pid = CreateChild(L"EDIT", L"0", ES_NUMBER | WS_TABSTOP,
                          WS_EX_CLIENTEDGE, IDC_PID);
  g_app.start =
      CreateChild(L"BUTTON", L"Start", BS_DEFPUSHBUTTON | WS_TABSTOP, 0,
                  IDC_START);
  g_app.cancel = CreateChild(L"BUTTON", L"Cancel",
                             BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_CANCEL);
  g_app.log = CreateChild(
      L"EDIT", L"",
      WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
      WS_EX_CLIENTEDGE, IDC_LOG);
  g_app.status = CreateChild(L"STATIC", L"Ready.",
                             SS_LEFT | SS_SUNKEN | SS_CENTERIMAGE, 0,
                             IDC_STATUS);

  const auto addCommand = [](Command command, const wchar_t* text) {
    const LRESULT index = SendMessageW(
        g_app.command, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text));
    if (index != CB_ERR) {
      SendMessageW(g_app.command, CB_SETITEMDATA, static_cast<WPARAM>(index),
                   static_cast<LPARAM>(command));
    }
  };
  addCommand(Command::Unpack, L"Unpack");
  addCommand(Command::Shrink, L"Shrink");
  addCommand(Command::MkData, L"Make data sections");
  addCommand(Command::DumpCode, L"Dump code");
  SendMessageW(g_app.command, CB_SETCURSEL, 0, 0);

  // Windows 2000-style UI font.  MS Sans Serif is the classic Win32 dialog
  // font; scaling keeps it readable on high-DPI displays.
  g_app.uiFont = CreateFontW(
      -MulDiv(8, g_dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
      DEFAULT_PITCH | FF_SWISS, L"MS Sans Serif");
  if (g_app.uiFont == nullptr) {
    g_app.uiFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  }

  g_app.logFont = CreateFontW(
      -MulDiv(9, g_dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
      FIXED_PITCH | FF_MODERN, L"Courier New");
  if (g_app.logFont == nullptr) {
    g_app.logFont = g_app.uiFont;
  }

  const HWND normalFontControls[] = {
      g_app.targetLabel, g_app.target,      g_app.browse,
      g_app.commandLabel, g_app.command,    g_app.pidLabel,   g_app.pid,
      g_app.start,        g_app.cancel,      g_app.status,
  };
  for (HWND control : normalFontControls) {
    SendMessageW(control, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_app.uiFont), TRUE);
  }
  SendMessageW(g_app.log, WM_SETFONT,
               reinterpret_cast<WPARAM>(g_app.logFont), TRUE);

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
  const int rowHeight = Dip(22);
  const int gap = Dip(6);
  const int labelHeight = Dip(18);
  const int width = client.right - 2 * margin;

  const int targetLabelWidth = Dip(44);
  const int browseWidth = Dip(60);
  const int commandLabelWidth = Dip(52);
  const int commandWidth = Dip(140);
  const int pidLabelWidth = Dip(30);
  const int pidEditWidth = Dip(48);
  const int startWidth = Dip(72);
  const int cancelWidth = Dip(72);

  int y = margin;
  MoveWindow(g_app.targetLabel, margin, y + Dip(2), targetLabelWidth,
             labelHeight, TRUE);
  MoveWindow(g_app.target, margin + targetLabelWidth + Dip(4), y,
             width - targetLabelWidth - Dip(4) - browseWidth - Dip(6),
             rowHeight, TRUE);
  MoveWindow(g_app.browse, margin + width - browseWidth, y, browseWidth,
             rowHeight, TRUE);

  y += rowHeight + gap;
  int x = margin;
  MoveWindow(g_app.commandLabel, x, y + Dip(2), commandLabelWidth,
             labelHeight, TRUE);
  x += commandLabelWidth + Dip(4);
  MoveWindow(g_app.command, x, y, commandWidth, Dip(160), TRUE);
  x += commandWidth + Dip(8);
  MoveWindow(g_app.pidLabel, x, y + Dip(2), pidLabelWidth, labelHeight, TRUE);
  x += pidLabelWidth + Dip(4);
  MoveWindow(g_app.pid, x, y, pidEditWidth, rowHeight, TRUE);
  MoveWindow(g_app.cancel, margin + width - startWidth - Dip(6) - cancelWidth,
             y, cancelWidth, rowHeight, TRUE);
  MoveWindow(g_app.start, margin + width - startWidth, y, startWidth,
             rowHeight, TRUE);

  y += rowHeight + gap;
  const int statusHeight = Dip(18);
  const int statusY = client.bottom - margin - statusHeight;
  MoveWindow(g_app.status, margin, statusY, width, statusHeight, TRUE);

  int logHeight = statusY - gap - y;
  if (logHeight < Dip(80)) {
    logHeight = Dip(80);
  }
  MoveWindow(g_app.log, margin, y, width, logHeight, TRUE);
}

void CopyLog() {
  if (g_app.log == nullptr) {
    return;
  }

  std::wstring text;
  DWORD start = 0;
  DWORD end = 0;
  SendMessageW(g_app.log, EM_GETSEL, reinterpret_cast<WPARAM>(&start),
               reinterpret_cast<LPARAM>(&end));
  if (end > start) {
    text.resize(static_cast<size_t>(end - start) + 1);
    const LRESULT copied = SendMessageW(
        g_app.log, EM_GETSELTEXT, 0,
        reinterpret_cast<LPARAM>(text.data()));
    text.resize(copied > 0 ? static_cast<size_t>(copied) : 0);
  } else {
    const int length = GetWindowTextLengthW(g_app.log);
    if (length <= 0) {
      return;
    }
    text.resize(static_cast<size_t>(length) + 1);
    GetWindowTextW(g_app.log, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
  }

  if (text.empty()) {
    return;
  }

  if (!OpenClipboard(g_app.hwnd)) {
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
  if (g_app.log == nullptr) {
    return;
  }

  wchar_t file[MAX_PATH]{};
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = g_app.hwnd;
  dialog.lpstrFilter = L"Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0";
  dialog.lpstrFile = file;
  dialog.nMaxFile = static_cast<DWORD>(_countof(file));
  dialog.lpstrDefExt = L"txt";
  dialog.lpstrTitle = L"Save log";
  dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
  if (!GetSaveFileNameW(&dialog)) {
    return;
  }

  const int length = GetWindowTextLengthW(g_app.log);
  std::wstring text(static_cast<size_t>(length) + 1, L'\0');
  if (length > 0) {
    GetWindowTextW(g_app.log, text.data(), length + 1);
  }
  text.resize(static_cast<size_t>(length));

  try {
    FileStream out(file, FileStream::Mode::Create);
    constexpr uint8_t bom[] = {0xEF, 0xBB, 0xBF};
    out.Write(bom, sizeof(bom));
    const std::string utf8 = WideToUtf8(text);
    if (!utf8.empty()) {
      out.Write(utf8.data(), utf8.size());
    }
    SetStatus(L"Log saved.");
  } catch (const std::exception& error) {
    MessageBoxW(g_app.hwnd, Utf8ToWide(error.what()).c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
  }
}

void ShowAbout() {
  std::wstring text = L"Magicmida ";
  text += Utf8ToWide(MAGICMIDA_VERSION);
  text += L"\n\nScyllaHide ";
  text += Utf8ToWide(scyllahide::Version());
  text += L" (embedded)\n\nUnpacks Themida/WinLicense protected binaries.";
  MessageBoxW(g_app.hwnd, text.c_str(), L"About Magicmida",
              MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam,
                         LPARAM lParam) {
  switch (message) {
    case WM_CREATE:
      CreateControls(hwnd);
      return 0;

    case WM_SIZE:
      Layout(hwnd);
      return 0;

    case WM_TIMER:
      if (wParam == kTargetTimerId) {
        KillTimer(hwnd, kTargetTimerId);
        UpdateCommandUi();
      }
      return 0;

    case WM_COMMAND: {
      const int id = LOWORD(wParam);
      const int notification = HIWORD(wParam);
      switch (id) {
        case IDC_BROWSE:
        case IDM_OPEN:
          BrowseForTarget();
          return 0;
        case IDC_START:
          StartJob();
          return 0;
        case IDC_CANCEL:
          if (g_app.running && g_app.cancelEvent != nullptr) {
            SetEvent(g_app.cancelEvent);
            EnableWindow(g_app.cancel, FALSE);
            SetStatus(L"Cancelling...");
          }
          return 0;
        case IDC_COMMAND:
          if (notification == CBN_SELCHANGE) {
            UpdateCommandUi();
          }
          return 0;
        case IDC_TARGET:
          if (notification == EN_CHANGE) {
            // Debounce: reading the PE flags on every keystroke can stall on
            // slow (network) paths.
            SetTimer(hwnd, kTargetTimerId, 250, nullptr);
          }
          return 0;
        case IDM_CLEAR_LOG:
          SetWindowTextW(g_app.log, L"");
          return 0;
        case IDM_SAVE_LOG:
          SaveLog();
          return 0;
        case IDM_COPY_LOG:
          CopyLog();
          return 0;
        case IDM_EXIT:
          PostMessageW(hwnd, WM_CLOSE, 0, 0);
          return 0;
        case IDM_ABOUT:
          ShowAbout();
          return 0;
        case IDM_ADV_DATA_SECTIONS:
          g_app.createDataSections = !g_app.createDataSections;
          UpdateAdvancedMenu();
          return 0;
        case IDM_ADV_NO_SCYLLA:
          g_app.disableScylla = !g_app.disableScylla;
          UpdateAdvancedMenu();
          return 0;
        case IDM_ADV_FIX_RELOCS:
          g_app.fixRelocations = !g_app.fixRelocations;
          UpdateAdvancedMenu();
          return 0;
        default:
          break;
      }
      break;
    }

    case WM_DROPFILES: {
      if (g_app.running) {
        DragFinish(reinterpret_cast<HDROP>(wParam));
        return 0;
      }
      auto drop = reinterpret_cast<HDROP>(wParam);
      const UINT length = DragQueryFileW(drop, 0, nullptr, 0);
      if (length > 0) {
        std::wstring path(static_cast<size_t>(length) + 1, L'\0');
        DragQueryFileW(drop, 0, path.data(), length + 1);
        path.resize(length);
        g_loggedTarget.clear();
        SetWindowTextW(g_app.target, path.c_str());
        UpdateCommandUi();
      }
      DragFinish(drop);
      return 0;
    }

    case kMsgLog: {
      auto* entry = reinterpret_cast<LogEntry*>(lParam);
      if (entry != nullptr) {
        AppendLog(entry->type, entry->text);
        delete entry;
      }
      return 0;
    }

    case kMsgStatus: {
      auto* text = reinterpret_cast<std::string*>(lParam);
      if (text != nullptr) {
        SetStatus(Utf8ToWide(*text).c_str());
        delete text;
      }
      return 0;
    }

    case kMsgDone: {
      if (g_app.worker != nullptr) {
        WaitForSingleObject(g_app.worker, INFINITE);
        CloseHandle(g_app.worker);
        g_app.worker = nullptr;
      }
      if (g_app.cancelEvent != nullptr) {
        CloseHandle(g_app.cancelEvent);
        g_app.cancelEvent = nullptr;
      }
      g_app.cancelEventName.clear();
      SetCancellationEvent(nullptr);
      SetRunning(false);
      SetStatus(wParam != 0 ? L"Completed successfully."
                            : L"Failed. See the log.");
      return 0;
    }

    case WM_CLOSE:
      if (g_app.running) {
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
      if (g_app.cancelEvent != nullptr) {
        CloseHandle(g_app.cancelEvent);
        g_app.cancelEvent = nullptr;
      }
      if (g_app.worker != nullptr) {
        CloseHandle(g_app.worker);
        g_app.worker = nullptr;
      }
      if (g_app.accel != nullptr) {
        DestroyAcceleratorTable(g_app.accel);
        g_app.accel = nullptr;
      }
      if (g_app.logFont != nullptr && g_app.logFont != g_app.uiFont) {
        DeleteObject(g_app.logFont);
        g_app.logFont = nullptr;
      }
      if (g_app.uiFont != nullptr) {
        DeleteObject(g_app.uiFont);
        g_app.uiFont = nullptr;
      }
      DragAcceptFiles(hwnd, FALSE);
      PostQuitMessage(0);
      return 0;

    default:
      break;
  }

  return DefWindowProcW(hwnd, message, wParam, lParam);
}

char WorkerLogPrefix(LogMsgType type) {
  switch (type) {
    case LogMsgType::Good:
      return 'G';
    case LogMsgType::Warning:
      return 'W';
    case LogMsgType::Fatal:
      return 'F';
    case LogMsgType::Info:
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
  CliWrite("[" + Format("%02u:%02u:%02u", now.wHour, now.wMinute,
                         now.wSecond) +
           "] " + LogPrefix(type) + message + "\r\n");
}

void AttachCliConsole() {
  if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
    AllocConsole();
  }
  const HANDLE output = CreateFileW(
      L"CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, 0, nullptr);
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

int RunCommandLine(int argumentCount, wchar_t** arguments) {
  AttachCliConsole();

  Job job;
  bool commandSet = false;
  bool force = false;

  for (int i = 1; i < argumentCount; ++i) {
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
      job.command = Command::Unpack;
      commandSet = true;
    } else if (argument == L"--shrink") {
      job.command = Command::Shrink;
      commandSet = true;
    } else if (argument == L"--mkdata") {
      job.command = Command::MkData;
      commandSet = true;
    } else if (argument == L"--dumpcode") {
      job.command = Command::DumpCode;
      commandSet = true;
    } else if (argument == L"--info") {
      job.command = Command::Info;
      commandSet = true;
    } else if (argument == L"--fix-relocs") {
      job.fixRelocations = true;
    } else if (argument == L"--data-sections") {
      job.createDataSections = true;
    } else if (argument == L"--no-scylla") {
      job.useScyllaHide = false;
    } else if (argument == L"--force") {
      force = true;
    } else if (argument == L"--pid") {
      if (i + 1 >= argumentCount) {
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

  if (!commandSet || job.target.empty()) {
    PrintUsage();
    return 2;
  }
  if (job.command == Command::DumpCode && job.pid == 0) {
    CliWrite("error: --dumpcode needs --pid\n");
    return 2;
  }

  SetLog(CliLogSink);
  SetStatusReporter(nullptr);
  SetCancellationEvent(nullptr);

  std::wstring error;
  uint16_t machine = 0;
  if (!ResolveJob(&job, &machine, &error)) {
    Log(ltFatal, WideToUtf8(error));
    return 1;
  }

  PEFlags flags;
  try {
    flags = ReadPEFlags(job.target);
  } catch (...) {
  }

  if (job.fixRelocations && !flags.isDll) {
    Log(ltWarning, "--fix-relocs is only applied to DLL targets.");
    job.fixRelocations = false;
  }
  if (job.fixRelocations && job.command != Command::Unpack &&
      job.command != Command::Shrink) {
    Log(ltWarning, "--fix-relocs only applies to Unpack and Shrink.");
    job.fixRelocations = false;
  }
  if (job.createDataSections && job.command != Command::Unpack) {
    Log(ltWarning, "--data-sections only applies to Unpack.");
    job.createDataSections = false;
  }
  if (job.createDataSections && machine != IMAGE_FILE_MACHINE_I386) {
    Log(ltWarning, "--data-sections is only available for 32-bit targets.");
    job.createDataSections = false;
  }

  if (job.command == Command::Unpack) {
    const std::wstring output = MakeUnpackedFileName(job.target);
    if (FileExists(output) && !force) {
      LogF(ltFatal,
           "The output file already exists: %s (use --force to overwrite).",
           WideToUtf8(output).c_str());
      return 1;
    }
  }

  return ExecuteJob(job) ? 0 : 1;
}

int RunWorkerMode(int argumentCount, wchar_t** arguments) {
  if (argumentCount < 9) {
    return 2;
  }

  const int command = _wtoi(arguments[2]);
  if (command < static_cast<int>(Command::Unpack) ||
      command > static_cast<int>(Command::Info)) {
    return 2;
  }

  Job job;
  job.command = static_cast<Command>(command);
  job.pid = static_cast<DWORD>(wcstoul(arguments[3], nullptr, 10));
  job.createDataSections = wcscmp(arguments[4], L"1") == 0;
  job.useScyllaHide = wcscmp(arguments[5], L"0") != 0;
  job.fixRelocations = wcscmp(arguments[6], L"1") == 0;
  const std::wstring cancelName = arguments[7];
  job.target = arguments[8];
  job.useWorker = false;

  HANDLE cancelEvent = nullptr;
  if (!cancelName.empty() && cancelName != L"-") {
    cancelEvent = OpenEventW(SYNCHRONIZE, FALSE, cancelName.c_str());
    if (cancelEvent == nullptr) {
      LogF(ltWarning, "Could not open the cancellation event (error %lu).",
           GetLastError());
    }
  }

  SetCancellationEvent(cancelEvent);
  SetStatusReporter(WorkerStatusSink);
  SetLog(WorkerLogSink);
  const bool success = ExecuteJob(job);
  SetStatusReporter(nullptr);
  SetCancellationEvent(nullptr);
  if (cancelEvent != nullptr) {
    CloseHandle(cancelEvent);
  }
  return success ? 0 : 1;
}

}  // namespace

int WINAPI WinMain(HINSTANCE instance, HINSTANCE /*previous*/, LPSTR /*cmdLine*/,
                   int showCommand) {
  int argumentCount = 0;
  LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
  if (arguments != nullptr && argumentCount >= 2 &&
      _wcsicmp(arguments[1], L"--worker") == 0) {
    const int result = RunWorkerMode(argumentCount, arguments);
    LocalFree(arguments);
    return result;
  }

  if (arguments != nullptr && argumentCount >= 2 &&
      arguments[1][0] == L'-') {
    const int result = RunCommandLine(argumentCount, arguments);
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

  g_app.instance = instance;

  HDC screen = GetDC(nullptr);
  g_dpi = screen != nullptr ? GetDeviceCaps(screen, LOGPIXELSY) : 96;
  if (screen != nullptr) {
    ReleaseDC(nullptr, screen);
  }

  HMENU menu = CreateMenu();
  HMENU fileMenu = CreatePopupMenu();
  AppendMenuW(fileMenu, MF_STRING, IDM_OPEN, L"&Open...\tCtrl+O");
  AppendMenuW(fileMenu, MF_STRING, IDM_CLEAR_LOG, L"&Clear log");
  AppendMenuW(fileMenu, MF_STRING, IDM_SAVE_LOG, L"&Save log...\tCtrl+S");
  AppendMenuW(fileMenu, MF_STRING, IDM_COPY_LOG, L"&Copy log");
  AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(fileMenu, MF_STRING, IDM_EXIT, L"E&xit");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"&File");

  HMENU advancedMenu = CreatePopupMenu();
  AppendMenuW(advancedMenu, MF_STRING, IDM_ADV_DATA_SECTIONS,
              L"&Create data sections");
  AppendMenuW(advancedMenu, MF_STRING, IDM_ADV_NO_SCYLLA,
              L"&Disable ScyllaHide");
  AppendMenuW(advancedMenu, MF_STRING, IDM_ADV_FIX_RELOCS,
              L"&Fix DLL relocations");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(advancedMenu),
              L"&Advanced");
  g_app.menu = menu;
  g_app.advancedMenu = advancedMenu;

  HMENU helpMenu = CreatePopupMenu();
  AppendMenuW(helpMenu, MF_STRING, IDM_ABOUT, L"&About");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(helpMenu), L"&Help");

  WNDCLASSEXW windowClass{};
  windowClass.cbSize = sizeof(windowClass);
  windowClass.style = CS_HREDRAW | CS_VREDRAW;
  windowClass.lpfnWndProc = WndProc;
  windowClass.hInstance = instance;
  windowClass.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
  windowClass.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
  windowClass.hbrBackground =
      reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
  windowClass.lpszClassName = kWindowClass;
  windowClass.hIconSm = windowClass.hIcon;

  if (RegisterClassExW(&windowClass) == 0) {
    return 1;
  }

  const int maxWindowWidth =
      GetSystemMetrics(SM_CXSCREEN) - Dip(40);
  const int maxWindowHeight =
      GetSystemMetrics(SM_CYSCREEN) - Dip(80);
  const int windowWidth = std::min(Dip(900), maxWindowWidth);
  const int windowHeight = std::min(Dip(430), maxWindowHeight);

  // Fixed-size classic window: no thick frame and no maximize box.
  HWND hwnd = CreateWindowExW(
      0, kWindowClass, kWindowTitle,
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
          WS_CLIPCHILDREN,
      CW_USEDEFAULT, CW_USEDEFAULT, windowWidth, windowHeight, nullptr, menu,
      instance, nullptr);
  if (hwnd == nullptr) {
    return 1;
  }

  if (arguments != nullptr) {
    if (argumentCount >= 2 && arguments[1][0] != L'-') {
      SetWindowTextW(g_app.target, arguments[1]);
    }
    LocalFree(arguments);
    arguments = nullptr;
  }
  UpdateCommandUi();

  ACCEL accelerator[2]{};
  accelerator[0].fVirt = FVIRTKEY | FCONTROL;
  accelerator[0].key = 'O';
  accelerator[0].cmd = IDM_OPEN;
  accelerator[1].fVirt = FVIRTKEY | FCONTROL;
  accelerator[1].key = 'S';
  accelerator[1].cmd = IDM_SAVE_LOG;
  g_app.accel = CreateAcceleratorTableW(accelerator, 2);

  SetLog(GuiLogSink);
  SetStatusReporter(GuiStatusSink);
  LogF(ltInfo, "Magicmida %s GUI ready. ScyllaHide %s embedded.",
       MAGICMIDA_VERSION, scyllahide::Version());

  ShowWindow(hwnd, showCommand);
  UpdateWindow(hwnd);

  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    if (g_app.accel == nullptr ||
        !TranslateAcceleratorW(hwnd, g_app.accel, &message)) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
  }

  return static_cast<int>(message.wParam);
}
