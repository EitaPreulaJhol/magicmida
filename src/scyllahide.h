// Magicmida - C++ port
// Embedded ScyllaHide integration.
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_SCYLLAHIDE_H_
#define MAGICMIDA_SCYLLAHIDE_H_

#include <windows.h>

#include <string>

namespace magicmida::scyllahide {

// Subset of the ScyllaHide "Magicmida" profile that is compiled into the
// executable.  Keeping it in C++ means no scylla_hide.ini has to be shipped.
struct Profile {
  bool hook_get_local_time = false;
  bool hook_get_system_time = false;
  bool hook_get_tick_count = false;
  bool hook_get_tick_count64 = false;
  bool hook_ki_user_exception_dispatcher = false;
  bool hook_nt_close = false;
  bool hook_nt_continue = false;
  bool hook_nt_create_thread_ex = false;
  bool hook_nt_get_context_thread = true;
  bool hook_nt_query_information_process = true;
  bool hook_nt_query_object = false;
  bool hook_nt_query_performance_counter = false;
  bool hook_nt_query_system_information = true;
  bool hook_nt_query_system_time = false;
  bool hook_nt_set_context_thread = false;
  bool hook_nt_set_debug_filter_state = false;
  bool hook_nt_set_information_thread = true;
  bool hook_nt_set_information_process = false;
  bool hook_nt_user_block_input = false;
  bool hook_nt_user_build_hwnd_list = false;
  bool hook_nt_user_find_window_ex = false;
  bool hook_nt_user_query_window = false;
  bool hook_nt_user_get_foreground_window = true;
  bool hook_nt_yield_execution = false;
  bool hook_output_debug_string_a = false;

  bool fix_peb_being_debugged = true;
  bool fix_peb_heap_flags = true;
  bool fix_peb_nt_global_flag = true;
  bool fix_peb_startup_info = false;
  bool fix_peb_os_build_number = false;
  bool prevent_thread_creation = false;
};

// Pinned ScyllaHide commit, shown by --version and the debug log.
const char* Version();

const Profile& DefaultProfile();

// Injects the embedded hook library into `process`, which must already be
// stopped by the debugger (typically at CREATE_PROCESS_DEBUG_EVENT).
// Returns false and fills `error` on failure.
bool Start(HANDLE process, DWORD process_id, const Profile& profile,
           std::string* error);

// Called for LOAD_DLL_DEBUG_EVENT. Applies the user32 hooks when user32.dll
// (or win32u.dll) becomes available. The win32u attempt can fail transiently
// before user32 finishes initializing; only a failure on user32 is warned.
void OnDllLoad(const std::wstring& file_name);

// Drops the session state.  The target is not unhooked; it normally exits
// after unpacking.
void Stop();

}  // namespace magicmida::scyllahide

#endif  // MAGICMIDA_SCYLLAHIDE_H_
