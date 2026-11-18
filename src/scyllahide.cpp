// Magicmida - C++ port
// Embedded ScyllaHide integration: resource loading, manual mapping, hook
// installation and deferred user32/win32u hooking.
#include "scyllahide.h"

#include "common.h"

#include <windows.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "HookLibrary/HookMain.h"
#include "InjectorCLI/ApplyHooking.h"
#include "InjectorCLI/DynamicMapping.h"
#include "Scylla/Logger.h"
#include "Scylla/PebHider.h"
#include "Scylla/User32Loader.h"
#include "Scylla/VersionPatch.h"

// The ScyllaHide injector sources expect a global `scl::Logger g_log`.  We
// never open a log file; callbacks are installed in Start() so messages go to
// magicmida's log.  This is the one vendor-required exception to the rule
// against static objects with non-trivial destructors.
scl::Logger g_log;

namespace magicmida {
namespace scyllahide {
namespace {

constexpr WORD kScyllaHookResourceId = 102;
constexpr WORD kRtRcData = 10;

struct Session {
  HANDLE process = nullptr;
  std::vector<uint8_t> image;
  void* remote_base = nullptr;
  HOOK_DLL_DATA hook_data{};

  ~Session() {
    if (process != nullptr) {
      CloseHandle(process);
    }
  }
};

Session*& CurrentSession() {
  static Session* session = nullptr;
  return session;
}

void ScyllaLogInfo(const wchar_t* msg) {
  LogF(kLogInfo, "ScyllaHide: %s", WideToUtf8(msg).c_str());
}

void ScyllaLogError(const wchar_t* msg) {
  LogF(kLogFatal, "ScyllaHide: %s", WideToUtf8(msg).c_str());
}

void ScyllaLogDebug(const wchar_t* msg) {
  LogF(kLogInfo, "ScyllaHide: %s", WideToUtf8(msg).c_str());
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

  add("GetLocalTime", profile.hook_get_local_time);
  add("GetSystemTime", profile.hook_get_system_time);
  add("GetTickCount", profile.hook_get_tick_count);
  add("GetTickCount64", profile.hook_get_tick_count64);
  add("KiUserExceptionDispatcher", profile.hook_ki_user_exception_dispatcher);
  add("NtClose", profile.hook_nt_close);
  add("NtContinue", profile.hook_nt_continue);
  add("NtCreateThreadEx", profile.hook_nt_create_thread_ex);
  add("NtGetContextThread", profile.hook_nt_get_context_thread);
  add("NtQueryInformationProcess", profile.hook_nt_query_information_process);
  add("NtQueryObject", profile.hook_nt_query_object);
  add("NtQueryPerformanceCounter", profile.hook_nt_query_performance_counter);
  add("NtQuerySystemInformation", profile.hook_nt_query_system_information);
  add("NtQuerySystemTime", profile.hook_nt_query_system_time);
  add("NtSetContextThread", profile.hook_nt_set_context_thread);
  add("NtSetDebugFilterState", profile.hook_nt_set_debug_filter_state);
  add("NtSetInformationThread", profile.hook_nt_set_information_thread);
  add("NtSetInformationProcess", profile.hook_nt_set_information_process);
  add("NtUserBlockInput", profile.hook_nt_user_block_input);
  add("NtUserBuildHwndList", profile.hook_nt_user_build_hwnd_list);
  add("NtUserFindWindowEx", profile.hook_nt_user_find_window_ex);
  add("NtUserQueryWindow", profile.hook_nt_user_query_window);
  add("NtUserGetForegroundWindow", profile.hook_nt_user_get_foreground_window);
  add("NtYieldExecution", profile.hook_nt_yield_execution);
  add("OutputDebugStringA", profile.hook_output_debug_string_a);
  add("PreventThreadCreation", profile.prevent_thread_creation);

  LogF(kLogInfo, "ScyllaHide %s profile hooks: %s", Version(),
       hooks.empty() ? "(none)" : hooks.c_str());
  LogF(kLogInfo,
       "ScyllaHide %s PEB patches: being=%d heap=%d ntglobal=%d startup=%d "
       "osbuild=%d",
       Version(), profile.fix_peb_being_debugged, profile.fix_peb_heap_flags,
       profile.fix_peb_nt_global_flag, profile.fix_peb_startup_info,
       profile.fix_peb_os_build_number);
}

bool DebugLoggingEnabled() {
  wchar_t value[8]{};
  const DWORD length = GetEnvironmentVariableW(L"MAGICMIDA_SCYLLA_DEBUG", value,
                                               _countof(value));
  return length != 0 && length < _countof(value);
}

bool ReadNtApiInformation(HOOK_DLL_DATA* hdd) {
  scl::User32Loader loader;
  if (!loader.FindSyscalls({"NtUserBlockInput", "NtUserBuildHwndList",
                            "NtUserFindWindowEx", "NtUserQueryWindow",
                            "NtUserGetForegroundWindow", "NtUserGetClassName",
                            "NtUserInternalGetWindowText",
                            "NtUserGetThreadState"})) {
    Log(kLogWarning, "ScyllaHide: failed to resolve user32/win32u syscalls");
    return false;
  }

  hdd->NtUserBlockInputVA = loader.GetUserSyscallVa("NtUserBlockInput");
  hdd->NtUserQueryWindowVA = loader.GetUserSyscallVa("NtUserQueryWindow");
  hdd->NtUserGetForegroundWindowVA =
      loader.GetUserSyscallVa("NtUserGetForegroundWindow");
  hdd->NtUserBuildHwndListVA = loader.GetUserSyscallVa("NtUserBuildHwndList");
  hdd->NtUserFindWindowExVA = loader.GetUserSyscallVa("NtUserFindWindowEx");
  hdd->NtUserGetClassNameVA = loader.GetUserSyscallVa("NtUserGetClassName");
  hdd->NtUserInternalGetWindowTextVA =
      loader.GetUserSyscallVa("NtUserInternalGetWindowText");
  hdd->NtUserGetThreadStateVA = loader.GetUserSyscallVa("NtUserGetThreadState");
  return true;
}

void FillHookDllData(HOOK_DLL_DATA* hdd, const Profile& profile) {
  hdd->EnableGetLocalTimeHook = profile.hook_get_local_time;
  hdd->EnableGetSystemTimeHook = profile.hook_get_system_time;
  hdd->EnableGetTickCountHook = profile.hook_get_tick_count;
  hdd->EnableGetTickCount64Hook = profile.hook_get_tick_count64;
  hdd->EnableKiUserExceptionDispatcherHook =
      profile.hook_ki_user_exception_dispatcher;
  hdd->EnableNtCloseHook = profile.hook_nt_close;
  hdd->EnableNtContinueHook = profile.hook_nt_continue;
  hdd->EnableNtCreateThreadExHook = profile.hook_nt_create_thread_ex;
  hdd->EnableNtGetContextThreadHook = profile.hook_nt_get_context_thread;
  hdd->EnableNtQueryInformationProcessHook =
      profile.hook_nt_query_information_process;
  hdd->EnableNtQueryObjectHook = profile.hook_nt_query_object;
  hdd->EnableNtQueryPerformanceCounterHook =
      profile.hook_nt_query_performance_counter;
  hdd->EnableNtQuerySystemInformationHook =
      profile.hook_nt_query_system_information;
  hdd->EnableNtQuerySystemTimeHook = profile.hook_nt_query_system_time;
  hdd->EnableNtSetContextThreadHook = profile.hook_nt_set_context_thread;
  hdd->EnableNtSetDebugFilterStateHook = profile.hook_nt_set_debug_filter_state;
  hdd->EnableNtSetInformationThreadHook =
      profile.hook_nt_set_information_thread;
  hdd->EnableNtSetInformationProcessHook =
      profile.hook_nt_set_information_process;
  hdd->EnableNtUserBlockInputHook = profile.hook_nt_user_block_input;
  hdd->EnableNtUserBuildHwndListHook = profile.hook_nt_user_build_hwnd_list;
  hdd->EnableNtUserFindWindowExHook = profile.hook_nt_user_find_window_ex;
  hdd->EnableNtUserQueryWindowHook = profile.hook_nt_user_query_window;
  hdd->EnableNtUserGetForegroundWindowHook =
      profile.hook_nt_user_get_foreground_window;
  hdd->EnableNtYieldExecutionHook = profile.hook_nt_yield_execution;
  hdd->EnableOutputDebugStringHook = profile.hook_output_debug_string_a;

  hdd->EnablePebBeingDebugged = profile.fix_peb_being_debugged;
  hdd->EnablePebHeapFlags = profile.fix_peb_heap_flags;
  hdd->EnablePebNtGlobalFlag = profile.fix_peb_nt_global_flag;
  hdd->EnablePebStartupInfo = profile.fix_peb_startup_info;
  hdd->EnablePebOsBuildNumber = profile.fix_peb_os_build_number;
  hdd->EnablePreventThreadCreation = profile.prevent_thread_creation;

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
             session.process, static_cast<uint8_t*>(session.remote_base) + rva,
             &session.hook_data, sizeof(session.hook_data), nullptr) != FALSE;
}

bool LoadEmbeddedHookLibrary(std::vector<uint8_t>* image, std::string* error) {
  const HRSRC resource =
      FindResourceW(nullptr, MAKEINTRESOURCEW(kScyllaHookResourceId),
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
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
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

  constexpr WORD kExpectedMachine =
      sizeof(void*) == 4 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
  if (nt->FileHeader.Machine != kExpectedMachine) {
    *error = "embedded ScyllaHide hook library has the wrong architecture";
    return false;
  }

  image->assign(static_cast<const uint8_t*>(data),
                static_cast<const uint8_t*>(data) + size);
  return true;
}

bool ApplyUserHooks(Session& session) {
  if (session.hook_data.isUserDllHooked) {
    return true;
  }

  if (!ApplyHook(&session.hook_data, session.process, session.image.data(),
                 reinterpret_cast<DWORD_PTR>(session.remote_base))) {
    return false;
  }
  if (!session.hook_data.isUserDllHooked) {
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

bool Start(HANDLE process, DWORD process_id, const Profile& profile,
           std::string* error) {
  std::string ignored_error;
  if (error == nullptr) {
    error = &ignored_error;
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
  if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(),
                       &session->process, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
    *error = "could not duplicate the process handle";
    return false;
  }

  if (!LoadEmbeddedHookLibrary(&session->image, error)) {
    return false;
  }

  Profile effective = profile;
  bool user_api_resolved = false;
  try {
    user_api_resolved = ReadNtApiInformation(&session->hook_data);
  } catch (...) {
    user_api_resolved = false;
  }
  if (!user_api_resolved) {
    // The core ntdll/kernel32 hooks still work.  Disable the optional user32
    // hooks instead of failing the whole injection.
    effective.hook_nt_user_block_input = false;
    effective.hook_nt_user_build_hwnd_list = false;
    effective.hook_nt_user_find_window_ex = false;
    effective.hook_nt_user_query_window = false;
    effective.hook_nt_user_get_foreground_window = false;
  }
  FillHookDllData(&session->hook_data, effective);

  DWORD peb_flags = 0;
  if (effective.fix_peb_being_debugged) {
    peb_flags |= PEB_PATCH_BeingDebugged;
  }
  if (effective.fix_peb_heap_flags) {
    peb_flags |= PEB_PATCH_HeapFlags;
  }
  if (effective.fix_peb_nt_global_flag) {
    peb_flags |= PEB_PATCH_NtGlobalFlag;
  }
  if (effective.fix_peb_startup_info) {
    peb_flags |= PEB_PATCH_ProcessParameters;
  }
  if (effective.fix_peb_os_build_number) {
    peb_flags |= PEB_PATCH_OsBuildNumber;
  }

  if (peb_flags != 0) {
    ApplyPEBPatch(process, peb_flags);
  }
  if (effective.fix_peb_os_build_number) {
    ApplyNtdllVersionPatch(process);
  }

  session->remote_base =
      MapModuleToProcess(process, session->image.data(), true);
  if (session->remote_base == nullptr) {
    *error = "mapping the ScyllaHide hook library failed";
    return false;
  }

  if (!ApplyHook(&session->hook_data, process, session->image.data(),
                 reinterpret_cast<DWORD_PTR>(session->remote_base))) {
    *error = "installing the ScyllaHide hooks failed";
    return false;
  }

  if (!WriteHookDllData(*session)) {
    *error = "writing ScyllaHide hook data failed";
    return false;
  }

  LogF(kLogGood, "ScyllaHide: hook library mapped at %p (pid %lu)",
       session->remote_base, process_id);
  CurrentSession() = session.release();
  return true;
}

void OnDllLoad(const std::wstring& file_name) {
  Session* session = CurrentSession();
  if (session == nullptr) {
    return;
  }
  if (session->hook_data.isUserDllHooked) {
    return;
  }

  const std::string lower = AsciiLowerCase(WideToUtf8(file_name));
  const bool is_user32 = lower.find("user32.dll") != std::string::npos;
  const bool is_win32u = lower.find("win32u.dll") != std::string::npos;
  if (!is_user32 && !is_win32u) {
    return;
  }

  if (ApplyUserHooks(*session)) {
    Log(kLogGood, "ScyllaHide: user32 hooks applied");
  } else if (is_user32) {
    Log(kLogWarning, "ScyllaHide: applying user32 hooks failed");
  } else {
    // win32u is mapped before user32 and the NtUser* stubs are not always
    // ready yet. The user32 event retries; only warn if that one fails.
    Log(kLogInfo,
        "ScyllaHide: user32 hooks will be applied when user32.dll loads");
  }
}

void Stop() {
  delete CurrentSession();
  CurrentSession() = nullptr;
}

}  // namespace scyllahide
}  // namespace magicmida

// Headless replacement for MessageBoxA used by the ScyllaHide injector.
extern "C" int ScyllaHideMessageBoxA(HWND /*window*/, LPCSTR lp_text,
                                     LPCSTR lp_caption, UINT u_type) {
  const UINT icon = u_type & MB_ICONMASK;
  const bool is_error =
      icon == MB_ICONERROR || icon == MB_ICONHAND || icon == MB_ICONSTOP;
  const bool is_warning = icon == MB_ICONWARNING || icon == MB_ICONEXCLAMATION;
  const magicmida::LogMsgType type =
      is_error ? magicmida::kLogFatal
               : (is_warning ? magicmida::kLogWarning : magicmida::kLogInfo);
  magicmida::LogF(type, "ScyllaHide: %s: %s",
                  lp_caption != nullptr ? lp_caption : "?",
                  lp_text != nullptr ? lp_text : "");
  return 0;
}
