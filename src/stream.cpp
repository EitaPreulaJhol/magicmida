// Magicmida - C++ port
// Minimal TStream replacements (TFileStream / TMemoryStream).
#include "stream.h"

#include <algorithm>
#include <limits>

namespace magicmida {
namespace {

DWORD ToMoveMethod(Stream::Origin origin) {
  switch (origin) {
    case Stream::Origin::Begin:
      return FILE_BEGIN;
    case Stream::Origin::Current:
      return FILE_CURRENT;
    case Stream::Origin::End:
      return FILE_END;
  }
  return FILE_BEGIN;
}

[[noreturn]] void ThrowLastError(const char* what) {
  throw std::runtime_error(Format("%s failed (error %lu)", what, GetLastError()));
}

}  // namespace

void Stream::CopyFrom(Stream& source, int64_t count) {
  if (count < 0) {
    return;
  }

  std::vector<uint8_t> chunk(static_cast<size_t>(std::min<int64_t>(count, 64 * 1024)));
  int64_t remaining = count;
  while (remaining > 0) {
    const size_t toRead =
        static_cast<size_t>(std::min<int64_t>(remaining, static_cast<int64_t>(chunk.size())));
    source.Read(chunk.data(), toRead);
    Write(chunk.data(), toRead);
    remaining -= static_cast<int64_t>(toRead);
  }
}

// --------------------------------------------------------------------------
// FileStream
// --------------------------------------------------------------------------

FileStream::FileStream(const std::wstring& path, Mode mode) {
  DWORD access = GENERIC_READ;
  DWORD share = FILE_SHARE_READ;
  DWORD disposition = OPEN_EXISTING;

  switch (mode) {
    case Mode::Read:
      access = GENERIC_READ;
      share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
      disposition = OPEN_EXISTING;
      break;
    case Mode::ReadWrite:
      access = GENERIC_READ | GENERIC_WRITE;
      share = FILE_SHARE_READ | FILE_SHARE_WRITE;
      disposition = OPEN_EXISTING;
      break;
    case Mode::Create:
      access = GENERIC_READ | GENERIC_WRITE;
      share = 0;
      disposition = CREATE_ALWAYS;
      break;
  }

  handle_ = CreateFileW(path.c_str(), access, share, nullptr, disposition,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle_ == INVALID_HANDLE_VALUE) {
    throw std::runtime_error(Format("Opening '%s' failed (error %lu)",
                                    WideToUtf8(path).c_str(), GetLastError()));
  }
}

FileStream::~FileStream() {
  if (handle_ != INVALID_HANDLE_VALUE) {
    CloseHandle(handle_);
  }
}

void FileStream::Read(void* buffer, size_t size) {
  uint8_t* cursor = static_cast<uint8_t*>(buffer);
  size_t remaining = size;
  while (remaining > 0) {
    const DWORD toRead = static_cast<DWORD>(
        std::min<size_t>(remaining, static_cast<size_t>(0x40000000)));
    DWORD read = 0;
    if (!ReadFile(handle_, cursor, toRead, &read, nullptr)) {
      ThrowLastError("ReadFile");
    }
    if (read == 0) {
      throw std::runtime_error("Unexpected end of file");
    }
    cursor += read;
    remaining -= read;
  }
}

void FileStream::Write(const void* buffer, size_t size) {
  const uint8_t* cursor = static_cast<const uint8_t*>(buffer);
  size_t remaining = size;
  while (remaining > 0) {
    const DWORD toWrite = static_cast<DWORD>(
        std::min<size_t>(remaining, static_cast<size_t>(0x40000000)));
    DWORD written = 0;
    if (!WriteFile(handle_, cursor, toWrite, &written, nullptr)) {
      ThrowLastError("WriteFile");
    }
    if (written == 0) {
      throw std::runtime_error("Writing to file failed");
    }
    cursor += written;
    remaining -= written;
  }
}

void FileStream::Seek(int64_t offset, Origin origin) {
  LARGE_INTEGER distance{};
  distance.QuadPart = offset;
  if (!SetFilePointerEx(handle_, distance, nullptr, ToMoveMethod(origin))) {
    ThrowLastError("SetFilePointerEx");
  }
}

int64_t FileStream::Position() {
  LARGE_INTEGER zero{};
  LARGE_INTEGER position{};
  if (!SetFilePointerEx(handle_, zero, &position, FILE_CURRENT)) {
    ThrowLastError("SetFilePointerEx");
  }
  return position.QuadPart;
}

int64_t FileStream::Size() {
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(handle_, &size)) {
    ThrowLastError("GetFileSizeEx");
  }
  return size.QuadPart;
}

// --------------------------------------------------------------------------
// MemoryStream
// --------------------------------------------------------------------------

void MemoryStream::LoadFromFile(const std::wstring& path) {
  FileStream file(path, FileStream::Mode::Read);
  const int64_t fileSize = file.Size();
  buffer_.resize(static_cast<size_t>(fileSize));
  position_ = 0;
  if (fileSize > 0) {
    file.Read(buffer_.data(), buffer_.size());
  }
}

void MemoryStream::SaveToFile(const std::wstring& path) {
  FileStream file(path, FileStream::Mode::Create);
  if (!buffer_.empty()) {
    file.Write(buffer_.data(), buffer_.size());
  }
}

void MemoryStream::Read(void* buffer, size_t size) {
  if (size == 0) {
    return;
  }
  if (position_ < 0 ||
      static_cast<uint64_t>(position_) + size > static_cast<uint64_t>(buffer_.size())) {
    throw std::runtime_error("MemoryStream read out of bounds");
  }
  std::memcpy(buffer, buffer_.data() + position_, size);
  position_ += static_cast<int64_t>(size);
}

void MemoryStream::Write(const void* buffer, size_t size) {
  if (size == 0) {
    return;
  }
  if (position_ < 0) {
    throw std::runtime_error("MemoryStream write with negative position");
  }
  EnsureCapacity(position_ + static_cast<int64_t>(size));
  std::memcpy(buffer_.data() + position_, buffer, size);
  position_ += static_cast<int64_t>(size);
}

void MemoryStream::Seek(int64_t offset, Origin origin) {
  int64_t base = 0;
  switch (origin) {
    case Origin::Begin:
      base = 0;
      break;
    case Origin::Current:
      base = position_;
      break;
    case Origin::End:
      base = static_cast<int64_t>(buffer_.size());
      break;
  }
  position_ = base + offset;
}

int64_t MemoryStream::Position() {
  return position_;
}

int64_t MemoryStream::Size() {
  return static_cast<int64_t>(buffer_.size());
}

void MemoryStream::SetSize(int64_t size) {
  buffer_.resize(static_cast<size_t>(std::max<int64_t>(size, 0)));
  position_ = std::min<int64_t>(position_, static_cast<int64_t>(buffer_.size()));
}

void MemoryStream::SetPosition(int64_t position) {
  if (position < 0) {
    throw std::runtime_error("MemoryStream position cannot be negative");
  }
  position_ = position;
}

void MemoryStream::EnsureCapacity(int64_t required) {
  if (required <= static_cast<int64_t>(buffer_.size())) {
    return;
  }
  buffer_.resize(static_cast<size_t>(required));
}

}  // namespace magicmida
