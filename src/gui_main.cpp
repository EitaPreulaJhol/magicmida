// Magicmida - C++ port
// Native Win32 GUI front-end.
#include "common.h"
#include "patcher.h"
#include "pe_report.h"
#include "reloc_fix.h"
#include "scyllahide.h"

#if defined(_WIN64)
#include "themida64.h"
#else
#include "themida32.h"
#endif

#include <windows.h>

#include <commdlg.h>
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

enum ControlId : int {
  IDC_TARGET_LABEL = 100,
  IDC_TARGET,
  IDC_BROWSE,
  IDC_COMMAND_LABEL,
  IDC_COMMAND,
  IDC_DATA_SECTIONS,
  IDC_NO_SCYLLA,
  IDC_FIX_RELOCS,
  IDC_PID_LABEL,
  IDC_PID,
  IDC_START,
  IDC_LOG,
  IDC_STATUS,
};

enum MenuId : int {
  IDM_OPEN = 200,
  IDM_CLEAR_LOG,
  IDM_EXIT,
  IDM_ABOUT,
};

constexpr UINT kMsgLog = WM_APP + 1;
constexpr UINT kMsgDone = WM_APP + 2;

struct LogEntry {
  LogMsgType type;
  std::string text;
};

struct AppState {
  HINSTANCE instance = nullptr;
  HWND hwnd = nullptr;
  HWND targetLabel = nullptr;
  HWND target = nullptr;
  HWND browse = nullptr;
  HWND commandLabel = nullptr;
  HWND command = nullptr;
  HWND dataSections = nullptr;
  HWND noScylla = nullptr;
  HWND fixRelocs = nullptr;
  HWND pidLabel = nullptr;
  HWND pid = nullptr;
  HWND start = nullptr;
  HWND log = nullptr;
  HWND status = nullptr;
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

  const std::string line =
      text.empty() ? std::string("\r\n")
                   : std::string(LogPrefix(type)) + text + "\r\n";
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

int SelectedCommand() {
  const int selection = static_cast<int>(
      SendMessageW(g_app.command, CB_GETCURSEL, 0, 0));
  if (selection < 0) {
    return -1;
  }
  return static_cast<int>(
      SendMessageW(g_app.command, CB_GETITEMDATA, selection, 0));
}

bool TargetIsDll() {
  const std::wstring target = GetText(g_app.target);
  if (target.empty() || !FileExists(target)) {
    return false;
  }
  try {
    return ReadPEIsDll(target);
  } catch (...) {
    return false;
  }
}

void UpdateCommandUi() {
  const int selection = SelectedCommand();
  const bool unpack = selection == static_cast<int>(Command::Unpack);
  const bool shrink = selection == static_cast<int>(Command::Shrink);
  const bool dumpCode = selection == static_cast<int>(Command::DumpCode);
  const bool enabled = !g_app.running;
  const bool dllTarget = (unpack || shrink) && TargetIsDll();

  EnableWindow(g_app.dataSections, enabled && unpack);
  EnableWindow(g_app.noScylla, enabled && unpack);
  EnableWindow(g_app.fixRelocs, enabled && dllTarget);
  EnableWindow(g_app.pidLabel, enabled && dumpCode);
  EnableWindow(g_app.pid, enabled && dumpCode);
}

void SetRunning(bool running) {
  g_app.running = running;

  EnableWindow(g_app.target, !running);
  EnableWindow(g_app.browse, !running);
  EnableWindow(g_app.command, !running);
  EnableWindow(g_app.start, !running);

  if (!running) {
    UpdateCommandUi();
  } else {
    EnableWindow(g_app.dataSections, FALSE);
    EnableWindow(g_app.noScylla, FALSE);
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
    SetWindowTextW(g_app.target, file);
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
  job->createDataSections =
      SendMessageW(g_app.dataSections, BM_GETCHECK, 0, 0) == BST_CHECKED;
  job->useScyllaHide =
      SendMessageW(g_app.noScylla, BM_GETCHECK, 0, 0) != BST_CHECKED;
  job->fixRelocations =
      SendMessageW(g_app.fixRelocs, BM_GETCHECK, 0, 0) == BST_CHECKED;
  job->pid = 0;

  if (job->target.empty()) {
    *error = L"Select a target file.";
    return false;
  }
  if (!FileExists(job->target)) {
    *error = L"Target file not found.";
    return false;
  }
  if (job->fixRelocations && !TargetIsDll()) {
    job->fixRelocations = false;
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
      (job.fixRelocations ? L"1" : L"0") + L" \"" + job.target + L"\"";

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

bool ExecuteJob(const Job& job) {
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
        break;
      }
      case Command::Shrink: {
        Patcher patcher(job.target);
        patcher.ProcessShrink();
        if (job.fixRelocations) {
          try {
            FixDllRelocations(job.target, 0);
          } catch (const std::exception& error) {
            LogF(ltWarning, "Relocation fix failed: %s", error.what());
          }
        }
        success = true;
        break;
      }
      case Command::MkData: {
        Patcher patcher(job.target);
        patcher.ProcessMkData();
        success = true;
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
  try {
    machine = ReadPEMachine(job.target);
  } catch (const std::exception& exception) {
    error = L"Could not read the target PE header: ";
    error += Utf8ToWide(exception.what());
    MessageBoxW(g_app.hwnd, error.c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
    return;
  }

#if defined(_WIN64)
  if (machine == IMAGE_FILE_MACHINE_I386) {
    // A 32-bit target is unpacked by the embedded 32-bit worker.
    job.useWorker = true;
  } else if (machine == IMAGE_FILE_MACHINE_AMD64) {
    job.useWorker = false;
    if (job.command == Command::MkData || job.command == Command::DumpCode) {
      error = L"MkData and Dump code are only available for 32-bit targets.";
      MessageBoxW(g_app.hwnd, error.c_str(), kWindowTitle,
                  MB_OK | MB_ICONWARNING);
      return;
    }
  } else {
    error = L"Unsupported target architecture.";
    MessageBoxW(g_app.hwnd, error.c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
    return;
  }
#else
  if (machine != IMAGE_FILE_MACHINE_I386) {
    error = L"This 32-bit build can only unpack 32-bit targets.";
    MessageBoxW(g_app.hwnd, error.c_str(), kWindowTitle,
                MB_OK | MB_ICONWARNING);
    return;
  }
#endif

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

  LogF(ltInfo, "Starting %s: %s", WideToUtf8(CommandName(job.command)).c_str(),
       WideToUtf8(job.target).c_str());
  SetRunning(true);
  SetStatus(L"Running...");

  auto* threadJob = new Job(job);
  HANDLE thread = CreateThread(nullptr, 0, RunJobThread, threadJob, 0, nullptr);
  if (thread == nullptr) {
    delete threadJob;
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
  g_app.dataSections = CreateChild(L"BUTTON", L"Create data sections",
                                   BS_AUTOCHECKBOX | WS_TABSTOP, 0,
                                   IDC_DATA_SECTIONS);
  g_app.noScylla = CreateChild(L"BUTTON", L"Disable ScyllaHide",
                               BS_AUTOCHECKBOX | WS_TABSTOP, 0,
                               IDC_NO_SCYLLA);
  g_app.fixRelocs = CreateChild(L"BUTTON", L"Fix DLL relocations",
                                BS_AUTOCHECKBOX | WS_TABSTOP, 0,
                                IDC_FIX_RELOCS);
  g_app.pidLabel =
      CreateChild(L"STATIC", L"PID:", SS_LEFT, 0, IDC_PID_LABEL);
  g_app.pid = CreateChild(L"EDIT", L"0", ES_NUMBER | WS_TABSTOP,
                          WS_EX_CLIENTEDGE, IDC_PID);
  g_app.start =
      CreateChild(L"BUTTON", L"Start", BS_DEFPUSHBUTTON | WS_TABSTOP, 0,
                  IDC_START);
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
  addCommand(Command::Info, L"Info");
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
      g_app.commandLabel, g_app.command,    g_app.dataSections,
      g_app.noScylla,     g_app.fixRelocs,   g_app.pidLabel,   g_app.pid,
      g_app.start,        g_app.status,
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
  const int dataSectionsWidth = Dip(124);
  const int noScyllaWidth = Dip(124);
  const int fixRelocsWidth = Dip(124);
  const int pidLabelWidth = Dip(30);
  const int pidEditWidth = Dip(48);
  const int startWidth = Dip(72);

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
  x += commandWidth + Dip(6);
  MoveWindow(g_app.dataSections, x, y + Dip(2), dataSectionsWidth,
             labelHeight, TRUE);
  x += dataSectionsWidth + Dip(6);
  MoveWindow(g_app.noScylla, x, y + Dip(2), noScyllaWidth, labelHeight, TRUE);
  x += noScyllaWidth + Dip(6);
  MoveWindow(g_app.fixRelocs, x, y + Dip(2), fixRelocsWidth, labelHeight, TRUE);
  x += fixRelocsWidth + Dip(8);
  MoveWindow(g_app.pidLabel, x, y + Dip(2), pidLabelWidth, labelHeight, TRUE);
  x += pidLabelWidth + Dip(4);
  MoveWindow(g_app.pid, x, y, pidEditWidth, rowHeight, TRUE);
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

void ShowAbout() {
  std::wstring text = L"Magicmida\n\nScyllaHide ";
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
        case IDC_COMMAND:
          if (notification == CBN_SELCHANGE) {
            UpdateCommandUi();
          }
          return 0;
        case IDC_TARGET:
          if (notification == EN_CHANGE) {
            UpdateCommandUi();
          }
          return 0;
        case IDM_CLEAR_LOG:
          SetWindowTextW(g_app.log, L"");
          return 0;
        case IDM_EXIT:
          PostMessageW(hwnd, WM_CLOSE, 0, 0);
          return 0;
        case IDM_ABOUT:
          ShowAbout();
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
        SetWindowTextW(g_app.target, path.c_str());
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

    case kMsgDone: {
      if (g_app.worker != nullptr) {
        WaitForSingleObject(g_app.worker, INFINITE);
        CloseHandle(g_app.worker);
        g_app.worker = nullptr;
      }
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

int RunWorkerMode(int argumentCount, wchar_t** arguments) {
  if (argumentCount < 8) {
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
  job.target = arguments[7];
  job.useWorker = false;

  SetLog(WorkerLogSink);
  return ExecuteJob(job) ? 0 : 1;
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
  AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(fileMenu, MF_STRING, IDM_EXIT, L"E&xit");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"&File");

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

  ACCEL accelerator{};
  accelerator.fVirt = FVIRTKEY | FCONTROL;
  accelerator.key = 'O';
  accelerator.cmd = IDM_OPEN;
  g_app.accel = CreateAcceleratorTableW(&accelerator, 1);

  SetLog(GuiLogSink);
  LogF(ltInfo, "Magicmida GUI ready. ScyllaHide %s embedded.",
       scyllahide::Version());

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
