// Magicmida - C++ port
// Embedded ScyllaHide integration.
#pragma once

#include <windows.h>

#include <string>

namespace magicmida {
namespace scyllahide {

// Subset of the ScyllaHide "Magicmida" profile that is compiled into the
// executable.  Keeping it in C++ means no scylla_hide.ini has to be shipped.
struct Profile {
  bool hookGetLocalTime = false;
  bool hookGetSystemTime = false;
  bool hookGetTickCount = false;
  bool hookGetTickCount64 = false;
  bool hookKiUserExceptionDispatcher = false;
  bool hookNtClose = false;
  bool hookNtContinue = false;
  bool hookNtCreateThreadEx = false;
  bool hookNtGetContextThread = true;
  bool hookNtQueryInformationProcess = true;
  bool hookNtQueryObject = false;
  bool hookNtQueryPerformanceCounter = false;
  bool hookNtQuerySystemInformation = true;
  bool hookNtQuerySystemTime = false;
  bool hookNtSetContextThread = false;
  bool hookNtSetDebugFilterState = false;
  bool hookNtSetInformationThread = true;
  bool hookNtSetInformationProcess = false;
  bool hookNtUserBlockInput = false;
  bool hookNtUserBuildHwndList = false;
  bool hookNtUserFindWindowEx = false;
  bool hookNtUserQueryWindow = false;
  bool hookNtUserGetForegroundWindow = true;
  bool hookNtYieldExecution = false;
  bool hookOutputDebugStringA = false;

  bool fixPebBeingDebugged = true;
  bool fixPebHeapFlags = true;
  bool fixPebNtGlobalFlag = true;
  bool fixPebStartupInfo = false;
  bool fixPebOsBuildNumber = false;
  bool preventThreadCreation = false;
};

// Pinned ScyllaHide commit, shown by --version and the debug log.
const char* Version();

const Profile& DefaultProfile();

// Injects the embedded hook library into `process`, which must already be
// stopped by the debugger (typically at CREATE_PROCESS_DEBUG_EVENT).
// Returns false and fills `error` on failure.
bool Start(HANDLE process, DWORD processId, const Profile& profile,
           std::string* error);

// Called for LOAD_DLL_DEBUG_EVENT. Applies the user32 hooks when user32.dll
// (or win32u.dll) becomes available. The win32u attempt can fail transiently
// before user32 finishes initializing; only a failure on user32 is warned.
void OnDllLoad(const std::wstring& fileName);

// Drops the session state.  The target is not unhooked; it normally exits
// after unpacking.
void Stop();

}  // namespace scyllahide
}  // namespace magicmida
