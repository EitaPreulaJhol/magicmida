// Magicmida - C++ port
// Embedded ScyllaHide integration: resource loading, manual mapping, hook
// installation and deferred user32/win32u hooking.
#include "scyllahide.h"

#include "common.h"

#include <windows.h>

#include <memory>
#include <vector>

#include "InjectorCLI/ApplyHooking.h"
#include "InjectorCLI/DynamicMapping.h"
#include "HookLibrary/HookMain.h"
#include "Scylla/Logger.h"
#include "Scylla/PebHider.h"
#include "Scylla/User32Loader.h"
#include "Scylla/VersionPatch.h"

// The ScyllaHide injector sources expect a global `scl::Logger g_log`.  We
// never open a log file; callbacks are installed in Start() so messages go to
// magicmida's log.
scl::Logger g_log;

namespace magicmida {
namespace scyllahide {
namespace {

constexpr WORD kScyllaHookResourceId = 102;
constexpr WORD kRtRcData = 10;

struct Session {
  HANDLE process = nullptr;
  std::vector<uint8_t> image;
  void* remoteBase = nullptr;
  HOOK_DLL_DATA hookData{};
};

std::unique_ptr<Session> g_session;

void ScyllaLogInfo(const wchar_t* msg) {
  LogF(ltInfo, "ScyllaHide: %s", WideToUtf8(msg).c_str());
}

void ScyllaLogError(const wchar_t* msg) {
  LogF(ltFatal, "ScyllaHide: %s", WideToUtf8(msg).c_str());
}

void ScyllaLogDebug(const wchar_t* msg) {
  LogF(ltInfo, "ScyllaHide: %s", WideToUtf8(msg).c_str());
}

void LogProfile(const Profile& profile) {
  std::string hooks;
  const auto add = [&hooks](const char* name, bool enabled) {
    if (!enabled) {
      return;
    }
    if (!hooks.empty()) {
      hooks += ", ";
    }
    hooks += name;
  };

  add("GetLocalTime", profile.hookGetLocalTime);
  add("GetSystemTime", profile.hookGetSystemTime);
  add("GetTickCount", profile.hookGetTickCount);
  add("GetTickCount64", profile.hookGetTickCount64);
  add("KiUserExceptionDispatcher", profile.hookKiUserExceptionDispatcher);
  add("NtClose", profile.hookNtClose);
  add("NtContinue", profile.hookNtContinue);
  add("NtCreateThreadEx", profile.hookNtCreateThreadEx);
  add("NtGetContextThread", profile.hookNtGetContextThread);
  add("NtQueryInformationProcess", profile.hookNtQueryInformationProcess);
  add("NtQueryObject", profile.hookNtQueryObject);
  add("NtQueryPerformanceCounter", profile.hookNtQueryPerformanceCounter);
  add("NtQuerySystemInformation", profile.hookNtQuerySystemInformation);
  add("NtQuerySystemTime", profile.hookNtQuerySystemTime);
  add("NtSetContextThread", profile.hookNtSetContextThread);
  add("NtSetDebugFilterState", profile.hookNtSetDebugFilterState);
  add("NtSetInformationThread", profile.hookNtSetInformationThread);
  add("NtSetInformationProcess", profile.hookNtSetInformationProcess);
  add("NtUserBlockInput", profile.hookNtUserBlockInput);
  add("NtUserBuildHwndList", profile.hookNtUserBuildHwndList);
  add("NtUserFindWindowEx", profile.hookNtUserFindWindowEx);
  add("NtUserQueryWindow", profile.hookNtUserQueryWindow);
  add("NtUserGetForegroundWindow", profile.hookNtUserGetForegroundWindow);
  add("NtYieldExecution", profile.hookNtYieldExecution);
  add("OutputDebugStringA", profile.hookOutputDebugStringA);
  add("PreventThreadCreation", profile.preventThreadCreation);

  LogF(ltInfo, "ScyllaHide %s profile hooks: %s", Version(),
       hooks.empty() ? "(none)" : hooks.c_str());
  LogF(ltInfo,
       "ScyllaHide %s PEB patches: being=%d heap=%d ntglobal=%d startup=%d "
       "osbuild=%d",
       Version(), profile.fixPebBeingDebugged, profile.fixPebHeapFlags,
       profile.fixPebNtGlobalFlag, profile.fixPebStartupInfo,
       profile.fixPebOsBuildNumber);
}

bool DebugLoggingEnabled() {
  wchar_t value[8]{};
  const DWORD length =
      GetEnvironmentVariableW(L"MAGICMIDA_SCYLLA_DEBUG", value, _countof(value));
  return length != 0 && length < _countof(value);
}

bool ReadNtApiInformation(HOOK_DLL_DATA* hdd) {
  scl::User32Loader loader;
  if (!loader.FindSyscalls({"NtUserBlockInput", "NtUserBuildHwndList",
                            "NtUserFindWindowEx", "NtUserQueryWindow",
                            "NtUserGetForegroundWindow", "NtUserGetClassName",
                            "NtUserInternalGetWindowText",
                            "NtUserGetThreadState"})) {
    Log(ltWarning, "ScyllaHide: failed to resolve user32/win32u syscalls");
    return false;
  }

  hdd->NtUserBlockInputVA = loader.GetUserSyscallVa("NtUserBlockInput");
  hdd->NtUserQueryWindowVA = loader.GetUserSyscallVa("NtUserQueryWindow");
  hdd->NtUserGetForegroundWindowVA =
      loader.GetUserSyscallVa("NtUserGetForegroundWindow");
  hdd->NtUserBuildHwndListVA =
      loader.GetUserSyscallVa("NtUserBuildHwndList");
  hdd->NtUserFindWindowExVA = loader.GetUserSyscallVa("NtUserFindWindowEx");
  hdd->NtUserGetClassNameVA = loader.GetUserSyscallVa("NtUserGetClassName");
  hdd->NtUserInternalGetWindowTextVA =
      loader.GetUserSyscallVa("NtUserInternalGetWindowText");
  hdd->NtUserGetThreadStateVA =
      loader.GetUserSyscallVa("NtUserGetThreadState");
  return true;
}

void FillHookDllData(HOOK_DLL_DATA* hdd, const Profile& profile) {
  hdd->EnableGetLocalTimeHook = profile.hookGetLocalTime;
  hdd->EnableGetSystemTimeHook = profile.hookGetSystemTime;
  hdd->EnableGetTickCountHook = profile.hookGetTickCount;
  hdd->EnableGetTickCount64Hook = profile.hookGetTickCount64;
  hdd->EnableKiUserExceptionDispatcherHook =
      profile.hookKiUserExceptionDispatcher;
  hdd->EnableNtCloseHook = profile.hookNtClose;
  hdd->EnableNtContinueHook = profile.hookNtContinue;
  hdd->EnableNtCreateThreadExHook = profile.hookNtCreateThreadEx;
  hdd->EnableNtGetContextThreadHook = profile.hookNtGetContextThread;
  hdd->EnableNtQueryInformationProcessHook =
      profile.hookNtQueryInformationProcess;
  hdd->EnableNtQueryObjectHook = profile.hookNtQueryObject;
  hdd->EnableNtQueryPerformanceCounterHook =
      profile.hookNtQueryPerformanceCounter;
  hdd->EnableNtQuerySystemInformationHook =
      profile.hookNtQuerySystemInformation;
  hdd->EnableNtQuerySystemTimeHook = profile.hookNtQuerySystemTime;
  hdd->EnableNtSetContextThreadHook = profile.hookNtSetContextThread;
  hdd->EnableNtSetDebugFilterStateHook = profile.hookNtSetDebugFilterState;
  hdd->EnableNtSetInformationThreadHook = profile.hookNtSetInformationThread;
  hdd->EnableNtSetInformationProcessHook = profile.hookNtSetInformationProcess;
  hdd->EnableNtUserBlockInputHook = profile.hookNtUserBlockInput;
  hdd->EnableNtUserBuildHwndListHook = profile.hookNtUserBuildHwndList;
  hdd->EnableNtUserFindWindowExHook = profile.hookNtUserFindWindowEx;
  hdd->EnableNtUserQueryWindowHook = profile.hookNtUserQueryWindow;
  hdd->EnableNtUserGetForegroundWindowHook =
      profile.hookNtUserGetForegroundWindow;
  hdd->EnableNtYieldExecutionHook = profile.hookNtYieldExecution;
  hdd->EnableOutputDebugStringHook = profile.hookOutputDebugStringA;

  hdd->EnablePebBeingDebugged = profile.fixPebBeingDebugged;
  hdd->EnablePebHeapFlags = profile.fixPebHeapFlags;
  hdd->EnablePebNtGlobalFlag = profile.fixPebNtGlobalFlag;
  hdd->EnablePebStartupInfo = profile.fixPebStartupInfo;
  hdd->EnablePebOsBuildNumber = profile.fixPebOsBuildNumber;
  hdd->EnablePreventThreadCreation = profile.preventThreadCreation;

  hdd->EnableMalwareRunPeUnpacker = FALSE;
  hdd->EnableProtectProcessId = FALSE;
  hdd->dwProtectedProcessId = 0;
  hdd->isNtdllHooked = FALSE;
  hdd->isKernel32Hooked = FALSE;
  hdd->isUserDllHooked = FALSE;
}

bool WriteHookDllData(Session& session) {
  const DWORD rva =
      GetDllFunctionAddressRVA(session.image.data(), "HookDllData");
  if (rva == 0) {
    return false;
  }
  return WriteProcessMemory(
             session.process,
             static_cast<uint8_t*>(session.remoteBase) + rva, &session.hookData,
             sizeof(session.hookData), nullptr) != FALSE;
}

bool LoadEmbeddedHookLibrary(std::vector<uint8_t>* image,
                             std::string* error) {
  const HRSRC resource = FindResourceW(
      nullptr, MAKEINTRESOURCEW(kScyllaHookResourceId),
      MAKEINTRESOURCEW(kRtRcData));
  if (resource == nullptr) {
    *error = "embedded ScyllaHide hook library not found";
    return false;
  }

  const DWORD size = SizeofResource(nullptr, resource);
  const HGLOBAL handle = LoadResource(nullptr, resource);
  const void* data = handle != nullptr ? LockResource(handle) : nullptr;
  if (data == nullptr || size < sizeof(IMAGE_DOS_HEADER)) {
    *error = "embedded ScyllaHide hook library is empty";
    return false;
  }

  const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(data);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
      dos->e_lfanew < 0 ||
      static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > size) {
    *error = "embedded ScyllaHide hook library has an invalid PE header";
    return false;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
      static_cast<const uint8_t*>(data) + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    *error = "embedded ScyllaHide hook library has an invalid PE signature";
    return false;
  }

  const WORD expectedMachine =
      sizeof(void*) == 4 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
  if (nt->FileHeader.Machine != expectedMachine) {
    *error = "embedded ScyllaHide hook library has the wrong architecture";
    return false;
  }

  image->assign(static_cast<const uint8_t*>(data),
                static_cast<const uint8_t*>(data) + size);
  return true;
}

bool ApplyUserHooks(Session& session) {
  if (session.hookData.isUserDllHooked) {
    return true;
  }

  if (!ApplyHook(&session.hookData, session.process, session.image.data(),
                 reinterpret_cast<DWORD_PTR>(session.remoteBase))) {
    return false;
  }
  if (!session.hookData.isUserDllHooked) {
    return false;
  }
  return WriteHookDllData(session);
}

}  // namespace

const char* Version() {
  return "baa5c8e";
}

const Profile& DefaultProfile() {
  static const Profile profile;
  return profile;
}

bool Start(HANDLE process, DWORD processId, const Profile& profile,
           std::string* error) {
  static std::string ignoredError;
  if (error == nullptr) {
    error = &ignoredError;
  }
  Stop();

  if (process == nullptr || process == INVALID_HANDLE_VALUE) {
    *error = "invalid process handle";
    return false;
  }

  g_log.SetLogCb(scl::Logger::Info, ScyllaLogInfo);
  g_log.SetLogCb(scl::Logger::Error, ScyllaLogError);
  if (DebugLoggingEnabled()) {
    g_log.SetLogCb(scl::Logger::Debug, ScyllaLogDebug);
    LogProfile(profile);
  }

  auto session = std::make_unique<Session>();
  session->process = process;

  if (!LoadEmbeddedHookLibrary(&session->image, error)) {
    return false;
  }

  Profile effective = profile;
  bool userApiResolved = false;
  try {
    userApiResolved = ReadNtApiInformation(&session->hookData);
  } catch (...) {
    userApiResolved = false;
  }
  if (!userApiResolved) {
    // The core ntdll/kernel32 hooks still work.  Disable the optional user32
    // hooks instead of failing the whole injection.
    effective.hookNtUserBlockInput = false;
    effective.hookNtUserBuildHwndList = false;
    effective.hookNtUserFindWindowEx = false;
    effective.hookNtUserQueryWindow = false;
    effective.hookNtUserGetForegroundWindow = false;
  }
  FillHookDllData(&session->hookData, effective);

  DWORD pebFlags = 0;
  if (effective.fixPebBeingDebugged) {
    pebFlags |= PEB_PATCH_BeingDebugged;
  }
  if (effective.fixPebHeapFlags) {
    pebFlags |= PEB_PATCH_HeapFlags;
  }
  if (effective.fixPebNtGlobalFlag) {
    pebFlags |= PEB_PATCH_NtGlobalFlag;
  }
  if (effective.fixPebStartupInfo) {
    pebFlags |= PEB_PATCH_ProcessParameters;
  }
  if (effective.fixPebOsBuildNumber) {
    pebFlags |= PEB_PATCH_OsBuildNumber;
  }

  if (pebFlags != 0) {
    ApplyPEBPatch(process, pebFlags);
  }
  if (effective.fixPebOsBuildNumber) {
    ApplyNtdllVersionPatch(process);
  }

  session->remoteBase = MapModuleToProcess(process, session->image.data(), true);
  if (session->remoteBase == nullptr) {
    *error = "mapping the ScyllaHide hook library failed";
    return false;
  }

  if (!ApplyHook(&session->hookData, process, session->image.data(),
                 reinterpret_cast<DWORD_PTR>(session->remoteBase))) {
    *error = "installing the ScyllaHide hooks failed";
    return false;
  }

  if (!WriteHookDllData(*session)) {
    *error = "writing ScyllaHide hook data failed";
    return false;
  }

  LogF(ltGood, "ScyllaHide: hook library mapped at %p (pid %lu)",
       session->remoteBase, processId);
  g_session = std::move(session);
  return true;
}

void OnDllLoad(const std::wstring& fileName) {
  if (!g_session) {
    return;
  }
  if (g_session->hookData.isUserDllHooked) {
    return;
  }

  const std::string lower = AsciiLowerCase(WideToUtf8(fileName));
  if (lower.find("user32.dll") == std::string::npos &&
      lower.find("win32u.dll") == std::string::npos) {
    return;
  }

  if (ApplyUserHooks(*g_session)) {
    Log(ltGood, "ScyllaHide: user32 hooks applied");
  } else {
    Log(ltWarning, "ScyllaHide: applying user32 hooks failed");
  }
}

void Stop() {
  g_session.reset();
}

}  // namespace scyllahide
}  // namespace magicmida

// Headless replacement for MessageBoxA used by the ScyllaHide injector.
extern "C" int ScyllaHideMessageBoxA(HWND /*hWnd*/, LPCSTR lpText,
                                     LPCSTR lpCaption, UINT uType) {
  const UINT icon = uType & MB_ICONMASK;
  const bool isError = icon == MB_ICONERROR || icon == MB_ICONHAND ||
                       icon == MB_ICONSTOP;
  const bool isWarning = icon == MB_ICONWARNING || icon == MB_ICONEXCLAMATION;
  const magicmida::LogMsgType type =
      isError ? magicmida::ltFatal
              : (isWarning ? magicmida::ltWarning : magicmida::ltInfo);
  magicmida::LogF(type, "ScyllaHide: %s: %s",
                  lpCaption != nullptr ? lpCaption : "?",
                  lpText != nullptr ? lpText : "");
  return 0;
}
