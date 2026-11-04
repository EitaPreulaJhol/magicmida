// Magicmida - C++ port
// Minimal TStream replacements (TFileStream / TMemoryStream).
#pragma once

#include "common.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace magicmida {

class Stream {
 public:
  enum class Origin { Begin, Current, End };

  virtual ~Stream() = default;

  // Reads exactly `size` bytes; throws on failure.
  virtual void Read(void* buffer, size_t size) = 0;
  virtual void Write(const void* buffer, size_t size) = 0;
  virtual void Seek(int64_t offset, Origin origin) = 0;
  virtual int64_t Position() = 0;
  virtual int64_t Size() = 0;

  // Copies `count` bytes from the current position of `source` into this stream
  // at its current position (TMemoryStream.CopyFrom semantics).
  void CopyFrom(Stream& source, int64_t count);
};

class FileStream final : public Stream {
 public:
  enum class Mode { Read, ReadWrite, Create };

  FileStream(const std::wstring& path, Mode mode);
  ~FileStream() override;

  FileStream(const FileStream&) = delete;
  FileStream& operator=(const FileStream&) = delete;

  void Read(void* buffer, size_t size) override;
  void Write(const void* buffer, size_t size) override;
  void Seek(int64_t offset, Origin origin) override;
  int64_t Position() override;
  int64_t Size() override;

 private:
  HANDLE handle_ = INVALID_HANDLE_VALUE;
};

class MemoryStream final : public Stream {
 public:
  MemoryStream() = default;

  void LoadFromFile(const std::wstring& path);
  void SaveToFile(const std::wstring& path);

  void Read(void* buffer, size_t size) override;
  void Write(const void* buffer, size_t size) override;
  void Seek(int64_t offset, Origin origin) override;
  int64_t Position() override;
  int64_t Size() override;

  uint8_t* Memory() { return buffer_.data(); }
  const uint8_t* Memory() const { return buffer_.data(); }

  void SetSize(int64_t size);
  void SetPosition(int64_t position);

 private:
  void EnsureCapacity(int64_t required);

  std::vector<uint8_t> buffer_;
  int64_t position_ = 0;
};

}  // namespace magicmida
