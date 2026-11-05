// Magicmida - C++ port
// Common helpers shared by all components.
#pragma once

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

// MinGW names the DEBUG_EVENT union ("u"), MSVC uses an anonymous union.
#if defined(_MSC_VER)
#define MM_EVENT_FIELD(event, field) ((event).field)
#else
#define MM_EVENT_FIELD(event, field) ((event).u.field)
#endif

namespace magicmida {

// --------------------------------------------------------------------------
// Logging
// --------------------------------------------------------------------------

enum class LogMsgType { Info, Good, Warning, Fatal };

constexpr LogMsgType ltInfo = LogMsgType::Info;
constexpr LogMsgType ltGood = LogMsgType::Good;
constexpr LogMsgType ltWarning = LogMsgType::Warning;
constexpr LogMsgType ltFatal = LogMsgType::Fatal;

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

// Builds "<dir><stem>U<ext>" like the original ChangeFileExt(FileName, 'U'+ext).
std::wstring MakeUnpackedFileName(const std::wstring& executable);

// --------------------------------------------------------------------------
// Memory regions
// --------------------------------------------------------------------------

struct MemoryRegion {
  uintptr_t Address = 0;
  size_t Size = 0;

  MemoryRegion() = default;
  MemoryRegion(uintptr_t address, size_t size) : Address(address), Size(size) {}

  bool Contains(uintptr_t address) const {
    return address >= Address && address < Address + Size;
  }
};

// --------------------------------------------------------------------------
// Pattern scanning
// --------------------------------------------------------------------------
//
// Patterns are hex byte pairs, e.g. "8B40??C3". A byte pair whose first
// character is '?' is treated as a wildcard (matching the original code).
// Returns the offset from `buf`, or 0 when the pattern was not found.

uint32_t FindDynamic(const std::string& pattern, const uint8_t* buf, size_t size);
uint32_t FindStatic(const std::string& pattern, const uint8_t* buf, size_t size);

// --------------------------------------------------------------------------
// Misc Win32 helpers (ported from Utils.pas)
// --------------------------------------------------------------------------

std::string AccessViolationFlagToStr(uint8_t flag);
uint32_t GetWindowsBuildNumber();
uint32_t GetWindowsMajorVersion();
uint32_t GetPETimestamp(const std::wstring& filename);

// NTSTATUS is not exposed by the lean public headers MinGW ships with.
using NtStatus = LONG;

extern "C" NtStatus __stdcall NtQueryInformationProcess(HANDLE processHandle,
                                                        DWORD processInformationClass,
                                                        PVOID processInformation,
                                                        DWORD processInformationLength,
                                                        PULONG returnLength);
extern "C" NtStatus __stdcall NtQueryInformationThread(HANDLE threadHandle,
                                                       DWORD threadInformationClass,
                                                       PVOID threadInformation,
                                                       DWORD threadInformationLength,
                                                       PULONG returnLength);
extern "C" LONG __stdcall RtlGetVersion(OSVERSIONINFOW* info);

// Windows structs missing from the public SDK headers.
struct ProcessBasicInformation {
  NtStatus ExitStatus;
  PVOID PebBaseAddress;
  ULONG_PTR AffinityMask;
  DWORD BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
};

struct ThreadBasicInformation {
  NtStatus ExitStatus;
  PVOID TebBaseAddress;
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
  ULONG_PTR AffinityMask;
  DWORD Priority;
  DWORD BasePriority;
};

constexpr NtStatus STATUS_SUCCESS_VALUE = 0;

}  // namespace magicmida
