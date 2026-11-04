// Magicmida - C++ port
// Common helpers shared by all components.
#include "common.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace magicmida {
namespace {

LogProc g_log;

void DefaultLog(LogMsgType type, const std::string& msg) {
  const char* prefix = "[Info] ";
  switch (type) {
    case LogMsgType::Good:
      prefix = "[Good] ";
      break;
    case LogMsgType::Warning:
      prefix = "[Warning] ";
      break;
    case LogMsgType::Fatal:
      prefix = "[Fatal] ";
      break;
    case LogMsgType::Info:
    default:
      break;
  }
  std::fputs(prefix, stdout);
  std::fputs(msg.c_str(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

int HexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool IsPathDelimiter(wchar_t c) {
  return c == L'\\' || c == L'/';
}

}  // namespace

// --------------------------------------------------------------------------
// Logging
// --------------------------------------------------------------------------

void SetLog(LogProc proc) {
  g_log = std::move(proc);
}

void Log(LogMsgType type, const std::string& msg) {
  if (g_log) {
    g_log(type, msg);
  } else {
    DefaultLog(type, msg);
  }
}

std::string Format(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  va_list copy;
  va_copy(copy, args);
  const int needed = std::vsnprintf(nullptr, 0, fmt, copy);
  va_end(copy);

  if (needed < 0) {
    va_end(args);
    return {};
  }

  std::string result(static_cast<size_t>(needed) + 1, '\0');
  std::vsnprintf(result.data(), result.size(), fmt, args);
  va_end(args);
  result.resize(static_cast<size_t>(needed));
  return result;
}

void LogF(LogMsgType type, const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  va_list copy;
  va_copy(copy, args);
  const int needed = std::vsnprintf(nullptr, 0, fmt, copy);
  va_end(copy);

  if (needed < 0) {
    va_end(args);
    return;
  }

  std::string result(static_cast<size_t>(needed) + 1, '\0');
  std::vsnprintf(result.data(), result.size(), fmt, args);
  va_end(args);
  result.resize(static_cast<size_t>(needed));
  Log(type, result);
}

// --------------------------------------------------------------------------
// Strings / paths
// --------------------------------------------------------------------------

std::string AsciiLowerCase(std::string value) {
  for (char& c : value) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return value;
}

bool AsciiSameText(std::string_view lhs, std::string_view rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (size_t i = 0; i < lhs.size(); ++i) {
    char a = lhs[i];
    char b = rhs[i];
    if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
    if (a != b) {
      return false;
    }
  }
  return true;
}

std::wstring Utf8ToWide(const std::string& value) {
  if (value.empty()) {
    return {};
  }
  const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0);
  if (length <= 0) {
    return {};
  }
  std::wstring result(static_cast<size_t>(length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      result.data(), length);
  return result;
}

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) {
    return {};
  }
  const int length = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0,
                                         nullptr, nullptr);
  if (length <= 0) {
    return {};
  }
  std::string result(static_cast<size_t>(length), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      result.data(), length, nullptr, nullptr);
  return result;
}

std::wstring ExtractFilePath(const std::wstring& path) {
  const size_t pos = path.find_last_of(L"\\/");
  if (pos == std::wstring::npos) {
    return {};
  }
  return path.substr(0, pos + 1);
}

std::wstring ExtractFileName(const std::wstring& path) {
  const size_t pos = path.find_last_of(L"\\/");
  if (pos == std::wstring::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

std::wstring ExtractFileExt(const std::wstring& path) {
  const std::wstring name = ExtractFileName(path);
  const size_t pos = name.find_last_of(L'.');
  if (pos == std::wstring::npos) {
    return {};
  }
  return name.substr(pos);
}

std::wstring ChangeFileExt(const std::wstring& path, const std::wstring& ext) {
  const std::wstring name = ExtractFileName(path);
  const size_t pos = name.find_last_of(L'.');
  if (pos == std::wstring::npos) {
    return path + ext;
  }
  return path.substr(0, path.size() - name.size() + pos) + ext;
}

std::wstring IncludeTrailingPathDelimiter(const std::wstring& path) {
  if (!path.empty() && IsPathDelimiter(path.back())) {
    return path;
  }
  return path + L'\\';
}

std::wstring RemoveTrailingPathDelimiter(const std::wstring& path) {
  std::wstring result = path;
  while (!result.empty() && IsPathDelimiter(result.back())) {
    result.pop_back();
  }
  return result;
}

bool FileExists(const std::wstring& path) {
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES &&
         (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring GetCurrentDir() {
  DWORD size = GetCurrentDirectoryW(0, nullptr);
  if (size == 0) {
    return {};
  }
  std::wstring result(size, L'\0');
  const DWORD written = GetCurrentDirectoryW(size, result.data());
  result.resize(written);
  return result;
}

std::wstring GetExecutablePath() {
  std::wstring result(MAX_PATH, L'\0');
  for (;;) {
    const DWORD written =
        GetModuleFileNameW(nullptr, result.data(), static_cast<DWORD>(result.size()));
    if (written == 0) {
      return {};
    }
    if (written < result.size()) {
      result.resize(written);
      return result;
    }
    result.resize(result.size() * 2);
  }
}

std::wstring MakeUnpackedFileName(const std::wstring& executable) {
  return ExtractFilePath(executable) +
         ChangeFileExt(ExtractFileName(executable), L"U" + ExtractFileExt(executable));
}

// --------------------------------------------------------------------------
// Pattern scanning
// --------------------------------------------------------------------------

namespace {

struct ParsedPattern {
  std::vector<uint8_t> bytes;
  std::vector<bool> wildcard;
};

ParsedPattern ParsePattern(const std::string& pattern) {
  ParsedPattern result;
  result.bytes.resize(pattern.size() / 2);
  result.wildcard.assign(pattern.size() / 2, false);

  for (size_t i = 0; i < pattern.size() / 2; ++i) {
    const char hi = pattern[i * 2];
    const char lo = pattern[i * 2 + 1];
    if (hi == '?') {
      result.wildcard[i] = true;
      result.bytes[i] = 0;
      continue;
    }
    const int high = HexDigit(hi);
    const int low = HexDigit(lo);
    if (high < 0 || low < 0) {
      throw std::runtime_error(Format("Invalid pattern byte at index %zu: '%c%c'",
                                      i * 2, hi, lo));
    }
    result.bytes[i] = static_cast<uint8_t>((high << 4) | low);
  }
  return result;
}

}  // namespace

uint32_t FindDynamic(const std::string& pattern, const uint8_t* buf, size_t size) {
  if (buf == nullptr || size == 0) {
    return 0;
  }

  const ParsedPattern parsed = ParsePattern(pattern);
  if (parsed.bytes.empty() || size < parsed.bytes.size()) {
    return 0;
  }

  // Keep the original's `buf < max` loop condition for behavioural parity.
  const uint8_t* const end = buf + size - parsed.bytes.size();
  for (const uint8_t* cursor = buf; cursor < end; ++cursor) {
    bool matched = true;
    for (size_t j = 0; j < parsed.bytes.size(); ++j) {
      if (!parsed.wildcard[j] && cursor[j] != parsed.bytes[j]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      return static_cast<uint32_t>(cursor - buf);
    }
  }
  return 0;
}

uint32_t FindStatic(const std::string& pattern, const uint8_t* buf, size_t size) {
  if (buf == nullptr || size == 0) {
    return 0;
  }

  const ParsedPattern parsed = ParsePattern(pattern);
  if (parsed.bytes.empty() || size < parsed.bytes.size()) {
    return 0;
  }

  const uint8_t* const end = buf + size - parsed.bytes.size();
  for (const uint8_t* cursor = buf; cursor < end; ++cursor) {
    if (std::memcmp(cursor, parsed.bytes.data(), parsed.bytes.size()) == 0) {
      return static_cast<uint32_t>(cursor - buf);
    }
  }
  return 0;
}

// --------------------------------------------------------------------------
// Misc Win32 helpers
// --------------------------------------------------------------------------

std::string AccessViolationFlagToStr(uint8_t flag) {
  switch (flag) {
    case 0:
      return "Read";
    case 1:
      return "Write";
    case 8:
      return "Execute";
    default:
      return std::to_string(flag);
  }
}

uint32_t GetWindowsBuildNumber() {
  OSVERSIONINFOW info{};
  info.dwOSVersionInfoSize = sizeof(info);
  RtlGetVersion(&info);
  return info.dwBuildNumber;
}

uint32_t GetWindowsMajorVersion() {
  OSVERSIONINFOW info{};
  info.dwOSVersionInfoSize = sizeof(info);
  RtlGetVersion(&info);
  return info.dwMajorVersion;
}

uint32_t GetPETimestamp(const std::wstring& filename) {
  HANDLE file = CreateFileW(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return 0;
  }

  uint8_t header[0x1000]{};
  DWORD read = 0;
  const BOOL ok = ReadFile(file, header, sizeof(header), &read, nullptr);
  CloseHandle(file);
  if (!ok || read < sizeof(IMAGE_DOS_HEADER)) {
    return 0;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
  if (static_cast<uint32_t>(dos->e_lfanew) > 0xF00) {
    return 0;
  }
  if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > read) {
    return 0;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(header + dos->e_lfanew);
  return nt->FileHeader.TimeDateStamp;
}

bool EnableDebugPrivilege() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    return false;
  }

  LUID luid{};
  if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
    CloseHandle(token);
    return false;
  }

  TOKEN_PRIVILEGES privileges{};
  privileges.PrivilegeCount = 1;
  privileges.Privileges[0].Luid = luid;
  privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  SetLastError(ERROR_SUCCESS);
  const BOOL adjusted =
      AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges),
                            nullptr, nullptr);
  const DWORD error = GetLastError();
  CloseHandle(token);
  return adjusted != FALSE && error == ERROR_SUCCESS;
}

}  // namespace magicmida