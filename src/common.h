// Magicmida - C++ port
// Common helpers shared by all components.
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_COMMON_H_
#define MAGICMIDA_COMMON_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Set by CMake from the project version. The fallback keeps standalone
// builds/tests compiling.
#ifndef MAGICMIDA_VERSION
#define MAGICMIDA_VERSION "dev"
#endif

#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// The Windows DEBUG_EVENT structure exposes its event payload through the
// named union `u` in both the Windows SDK and MinGW headers. Older SDKs had
// an anonymous union; the current SDK used by MSVC/VS 2026 does not.
#define MM_EVENT_FIELD(event, field) ((event).u.field)
// Portable wrapper for the 1-byte packed binary layouts used by the PE and
// BeaEngine structures.  The project does not need any other packing value.
#if defined(_MSC_VER)
#define MAGICMIDA_PACK_PUSH_1 __pragma(pack(push, 1))
#define MAGICMIDA_PACK_POP __pragma(pack(pop))
#else
#define MAGICMIDA_PACK_PUSH_1 _Pragma("pack(push, 1)")
#define MAGICMIDA_PACK_POP _Pragma("pack(pop)")
#endif

namespace magicmida {

// --------------------------------------------------------------------------
// Logging
// --------------------------------------------------------------------------

enum class LogMsgType { kInfo, kGood, kWarning, kFatal };

constexpr LogMsgType kLogInfo = LogMsgType::kInfo;
constexpr LogMsgType kLogGood = LogMsgType::kGood;
constexpr LogMsgType kLogWarning = LogMsgType::kWarning;
constexpr LogMsgType kLogFatal = LogMsgType::kFatal;

using LogProc = std::function<void(LogMsgType, const std::string&)>;

// Installs the global log sink. If none is set, messages go to stdout.
void SetLog(LogProc proc);

// Writes one log message through the installed sink (or stdout).
void Log(LogMsgType type, const std::string& msg);

// printf-style formatting helper.
std::string Format(const char* fmt, ...);

// printf-style logging helper.
void LogF(LogMsgType type, const char* fmt, ...);

// Optional status sink used to show the current unpacking stage.
using StatusProc = std::function<void(const std::string&)>;
void SetStatusReporter(StatusProc proc);
void ReportStatus(const std::string& text);

// Cancellation event shared by the GUI and the debug loop. The GUI creates
// and signals it; the debugger polls it.
void SetCancellationEvent(HANDLE event);
bool IsCancellationRequested();

// --------------------------------------------------------------------------
// Strings / paths (Delphi-compatible helpers)
// --------------------------------------------------------------------------

std::string AsciiLowerCase(std::string value);
bool AsciiSameText(std::string_view lhs, std::string_view rhs);

std::wstring Utf8ToWide(const std::string& value);
std::string WideToUtf8(const std::wstring& value);

std::wstring ExtractFilePath(const std::wstring& path);
std::wstring ExtractFileName(const std::wstring& path);
std::wstring ExtractFileExt(const std::wstring& path);
std::wstring ChangeFileExt(const std::wstring& path, const std::wstring& ext);
std::wstring IncludeTrailingPathDelimiter(const std::wstring& path);
std::wstring RemoveTrailingPathDelimiter(const std::wstring& path);

bool FileExists(const std::wstring& path);
std::wstring GetCurrentDir();
std::wstring GetExecutablePath();
bool EnableDebugPrivilege();

// Builds "<dir><stem>U<ext>" like the original ChangeFileExt(FileName,
// 'U'+ext).
std::wstring MakeUnpackedFileName(const std::wstring& executable);

// --------------------------------------------------------------------------
// Memory regions
// --------------------------------------------------------------------------

struct MemoryRegion {
  uintptr_t address = 0;
  size_t size = 0;

  MemoryRegion() = default;
  MemoryRegion(uintptr_t region_address, size_t region_size)
      : address(region_address), size(region_size) {}

  bool Contains(uintptr_t candidate) const {
    return candidate >= address && candidate < address + size;
  }
};

// --------------------------------------------------------------------------
// Pattern scanning
// --------------------------------------------------------------------------
//
// Patterns are hex byte pairs, e.g. "8B40??C3". A byte pair whose first
// character is '?' is treated as a wildcard (matching the original code).
// Returns the offset from `buf`, or 0 when the pattern was not found.

uint32_t FindDynamic(const std::string& pattern, const uint8_t* buf,
                     size_t size);
uint32_t FindStatic(const std::string& pattern, const uint8_t* buf,
                    size_t size);

// --------------------------------------------------------------------------
// Misc Win32 helpers (ported from Utils.pas)
// --------------------------------------------------------------------------

std::string AccessViolationFlagToStr(uint8_t flag);
uint32_t GetWindowsBuildNumber();
uint32_t GetWindowsMajorVersion();
uint32_t GetPeTimestamp(const std::wstring& filename);

// NTSTATUS is not exposed by the lean public headers MinGW ships with.
using NtStatus = LONG;

extern "C" LONG __stdcall RtlGetVersion(OSVERSIONINFOW* info);

// Windows structs missing from the public SDK headers.
struct ProcessBasicInformation {
  NtStatus exit_status;
  PVOID peb_base_address;
  ULONG_PTR affinity_mask;
  DWORD base_priority;
  ULONG_PTR unique_process_id;
  ULONG_PTR inherited_from_unique_process_id;
};

}  // namespace magicmida

#endif  // MAGICMIDA_COMMON_H_
