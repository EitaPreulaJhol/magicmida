// Magicmida - C++ port
// Shared Themida-unpacking logic (ported from ThemidaCommon.pas).
#include "themida_common.h"

#include "vm_entry.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace magicmida {
namespace {

std::string SafeString(const char* data, size_t maxLength) {
  size_t length = 0;
  while (length < maxLength && data[length] != '\0') {
    ++length;
  }
  return std::string(data, length);
}

uint32_t FindDelphiCall(const uint8_t* codeDump, uint32_t codeSize) {
  // Delphi has type metadata at its .text base rather than code.
  uint32_t i = 0;
  uint32_t counter = 0;
  while (i + 6 < codeSize) {
    if (*reinterpret_cast<const uint16_t*>(codeDump + i) == 0x25FF) {
      ++counter;
      if (counter == 3) {  // Skip the first two for good measure
        return i;
      }
    }
    ++i;
  }
  return 0;
}

uint32_t FindGoBuildIdEnd(const uint8_t* codeDump, uint32_t codeSize) {
  // Go has "Go build ID" at the start of .text.
  for (uint32_t i = 0; i + 2 <= codeSize; ++i) {
    if (*reinterpret_cast<const uint16_t*>(codeDump + i) == 0xFF20) {
      return i + 2;  // 20 FF marks the end
    }
  }
  return 0;
}

}  // namespace

void ThemidaCommon::InitPEDetails(IMAGE_NT_HEADERS* nt) {
  const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
      reinterpret_cast<const uint8_t*>(nt) + sizeof(IMAGE_NT_HEADERS));

  pe_sections_.assign(sections, sections + nt->FileHeader.NumberOfSections);

  if (pe_sections_.empty()) {
    throw std::runtime_error("The selected binary has no sections.");
  }

  if (nt->OptionalHeader.AddressOfEntryPoint <
      pe_sections_[0].VirtualAddress + pe_sections_[0].Misc.VirtualSize) {
    throw std::runtime_error(
        "The selected binary does not seem to be packed (entrypoint is in "
        ".text section).");
  }

  image_boundary_ = nt->OptionalHeader.SizeOfImage + image_base_;
  LogF(kLogInfo, "Image boundary: %p",
       reinterpret_cast<void*>(image_boundary_));

  major_linker_version_ = nt->OptionalHeader.MajorLinkerVersion;
  LogF(kLogInfo, "Image linker: %d.%d", major_linker_version_,
       nt->OptionalHeader.MinorLinkerVersion);
}

void ThemidaCommon::CheckVirtualizedOEP(uintptr_t oep) {
  if (tm_sect_r_.address == 0) {
    return;
  }

  const auto readStub = [&](uintptr_t address, VmStubInfo* info) -> bool {
    uint8_t code[16]{};
    if (!RPM(address, code, sizeof(code))) {
      return false;
    }
    *info = ParseVmStub(code, sizeof(code),
                        static_cast<uint32_t>(address - image_base_),
                        static_cast<uint64_t>(image_base_));
    return info->kind != VmStubKind::kNone;
  };

  VmStubInfo info;
  if (!readStub(oep, &info)) {
    return;
  }

  uintptr_t target = image_base_ + info.target_rva;
  if (info.kind == VmStubKind::kDirectJump ||
      info.kind == VmStubKind::kDirectCall ||
      info.kind == VmStubKind::kShortJump) {
    // The OEP may jump/call to a push;jmp entry stub instead of directly
    // into the VM. Follow one level when that target is not the VM itself.
    if (target < tm_sect_r_.address) {
      VmStubInfo next;
      if (readStub(target, &next)) {
        target = image_base_ + next.target_rva;
      }
    }
  }

  if (!pe_sections_.empty()) {
    const uintptr_t textStart = image_base_ + pe_sections_[0].VirtualAddress;
    const uintptr_t textEnd = textStart + pe_sections_[0].Misc.VirtualSize;
    if (target >= textStart && target < textEnd) {
      // A jump inside the application's code section is not the VM.
      return;
    }
  }

  if (target < tm_sect_r_.address ||
      (image_boundary_ != 0 && target >= image_boundary_)) {
    return;
  }

  is_vm_oep_ = true;
  LogF(kLogInfo, "OEP is virtualized (!): %llX -> %llX",
       static_cast<unsigned long long>(oep),
       static_cast<unsigned long long>(target));
  Log(kLogWarning,
      "The dump keeps the virtualized entry point. Shrink will keep the VM "
      "section; devirtualize the target before removing it.");
}

uintptr_t ThemidaCommon::DetermineIATAddress(uintptr_t oep, Dumper& dumper) {
  ReportStatus("Locating the IAT");
  uintptr_t textBase = 0;
  uintptr_t codeSize = 0;
  uintptr_t dataSize = 0;
  int dataSectionIndex = 0;
  uint8_t* codeDump = nullptr;
  uint32_t numInstr = 0;

  std::function<uintptr_t(uintptr_t, bool)> findCallOrJmpPtr =
      [&](uintptr_t address, bool ignoreMethodBoundary = false) -> uintptr_t {
    if (address < textBase || address >= textBase + codeSize) {
      return 0;
    }

    DISASM dis{};
    dis.EIP = reinterpret_cast<uintptr_t>(codeDump) + address - textBase;
    dis.VirtualAddr = address;

    while ((numInstr < 200) ||
           (ignoreMethodBoundary && (dis.VirtualAddr < textBase + codeSize))) {
      if (dis.VirtualAddr < textBase ||
          dis.VirtualAddr >= textBase + codeSize) {
        break;
      }

      const int len = DisasmCheck(dis);

      if (*reinterpret_cast<const uint16_t*>(dis.EIP) == 0x15FF ||
          *reinterpret_cast<const uint16_t*>(dis.EIP) == 0x25FF) {
        LogF(kLogInfo, "Found %08llX : %s",
             static_cast<unsigned long long>(dis.VirtualAddr),
             SafeString(dis.CompleteInstr, sizeof(dis.CompleteInstr)).c_str());
        uintptr_t iatPointer =
            static_cast<uintptr_t>(dis.Operand1.Memory.Displacement);
#if defined(_WIN64)
        iatPointer += dis.VirtualAddr + 6;  // RIP-relative
#endif
        // Ensure we didn't stumble upon a pointer into .text.
        uintptr_t thePointer = 0;
        if (!RPM(iatPointer, &thePointer, sizeof(thePointer)) ||
            thePointer > textBase + codeSize) {
          return iatPointer;
        }
      }

      if (*reinterpret_cast<const uint8_t*>(dis.EIP) == 0xE8 &&
          !ignoreMethodBoundary) {
        if (dis.Instruction.AddrValue < textBase ||
            dis.Instruction.AddrValue > textBase + codeSize) {
          return 0;  // 32-bit: probably direct API call. Handled below.
        }

        const uintptr_t result =
            findCallOrJmpPtr(dis.Instruction.AddrValue, false);
        if (result != 0) {
          return result;
        }
      }

      if ((*reinterpret_cast<const uint8_t*>(dis.EIP) == 0xC3 ||
           *reinterpret_cast<const uint8_t*>(dis.EIP) == 0xC2) &&
          !ignoreMethodBoundary) {
        return 0;
      }

      ++numInstr;
      if (len > 0) {
        dis.EIP += static_cast<uintptr_t>(len);
        dis.VirtualAddr += static_cast<uintptr_t>(len);
      } else {
        // Better luck next time...
        ++dis.EIP;
        ++dis.VirtualAddr;
      }
    }

    return 0;
  };

  auto findGoAPICall = [&](uintptr_t address) -> uintptr_t {
    DISASM dis{};
    dis.EIP = reinterpret_cast<uintptr_t>(codeDump) + address - textBase;
    dis.VirtualAddr = address;

    while (dis.VirtualAddr < textBase + codeSize) {
      const int len = DisasmCheck(dis);

      // mov rax, [addr]
      // mov [rsp], rax
#if defined(_WIN64)
      if (len == 7 && dis.Instruction.Opcode == 0x8B &&
          *reinterpret_cast<const uint32_t*>(dis.EIP + 7) == 0x24048948) {
#else
      if (len == 6 && dis.Instruction.Opcode == 0x8B &&
          (*reinterpret_cast<const uint32_t*>(dis.EIP + 6) & 0x00FFFFFF) ==
              0x00240489) {
#endif
        uintptr_t iatPointer =
            static_cast<uintptr_t>(dis.Operand2.Memory.Displacement);
#if defined(_WIN64)
        iatPointer += dis.VirtualAddr + 7;  // RIP-relative
#endif
        uintptr_t thePointer = 0;
        if (RPM(iatPointer, &thePointer, sizeof(thePointer)) &&
            dumper.IsAPIAddress(thePointer)) {
          return iatPointer;
        }
      }

      ++numInstr;
      if (len > 0) {
        dis.EIP += static_cast<uintptr_t>(len);
        dis.VirtualAddr += static_cast<uintptr_t>(len);
      } else {
        ++dis.EIP;
        ++dis.VirtualAddr;
      }
    }

    return 0;
  };  // NOLINT(readability/braces)

  std::function<uintptr_t(uintptr_t, bool)> scanData =
      [&](uintptr_t toFind, bool scanCode) -> uintptr_t {
    uintptr_t startOffset = 0;
    uintptr_t scanSize = 0;
    if (!scanCode) {
      startOffset = textBase + codeSize;
      scanSize = dataSize;
    } else {
      startOffset = textBase;
      scanSize = codeSize;
    }

    std::vector<uint8_t> dataSection(static_cast<size_t>(scanSize));
    if (!RPM(startOffset, dataSection.data(), dataSection.size())) {
      throw std::runtime_error("DetermineIATAddress.ScanData: RPM failed");
    }

    // We assume the table is machine-word aligned.
    const size_t count = dataSection.size() / sizeof(uintptr_t);
    const auto* walker = reinterpret_cast<const uintptr_t*>(dataSection.data());
    for (size_t index = 0; index < count; ++index) {
      if (walker[index] == toFind) {
        return startOffset + index * sizeof(uintptr_t);
      }
    }

    if (scanCode) {
      throw std::runtime_error("Unable to find API in section");
    }
    // Retry with first part of section in case of extreme merges (Themida V1).
    return scanData(toFind, true);
  };

  // For MSVC, the IAT often resides at image_base + baseOfData. Other compilers
  // such as Delphi use a dedicated .idata section, but the IAT doesn't start
  // directly at the beginning, so some guesswork is needed.
  dataSectionIndex = 0;
  for (size_t i = 0; i < pe_sections_.size(); ++i) {
    if (base_of_data_ <
        pe_sections_[i].VirtualAddress + pe_sections_[i].Misc.VirtualSize) {
      dataSectionIndex = static_cast<int>(i);
      break;
    }
  }

  textBase = image_base_ + pe_sections_[0].VirtualAddress;
  codeSize = base_of_data_ - pe_sections_[0].VirtualAddress;
  dataSize =
      pe_sections_[static_cast<size_t>(dataSectionIndex)].Misc.VirtualSize -
      (base_of_data_ -
       pe_sections_[static_cast<size_t>(dataSectionIndex)].VirtualAddress);
  LogF(kLogInfo, "Text base: 0x%.8llX, code size: 0x%llX, data size: 0x%llX",
       static_cast<unsigned long long>(textBase),
       static_cast<unsigned long long>(codeSize),
       static_cast<unsigned long long>(dataSize));
  numInstr = 0;

  // 16 bytes of zero padding let the decoder safely read a full instruction
  // at the end of the code section (matching the original's behaviour).
  std::vector<uint8_t> codeDumpStorage(static_cast<size_t>(codeSize) + 16, 0);
  codeDump = codeDumpStorage.data();
  {
    if (!RPM(textBase, codeDump, codeSize)) {
      throw std::runtime_error("DetermineIATAddress: RPM failed");
    }

    uintptr_t iatRef = 0;
    if (*reinterpret_cast<const uint32_t*>(codeDump) == 0x6F4720FF) {
      iatRef = findGoAPICall(
          textBase +
          FindGoBuildIdEnd(codeDump, static_cast<uint32_t>(codeSize)));
    } else if (!is_vm_oep_) {
      iatRef = findCallOrJmpPtr(oep, false);
    } else if (*reinterpret_cast<const uint32_t*>(
                   codeDump + (sizeof(void*) == 4 ? 6 : 10)) == 0x6C6F6F42 ||
               *reinterpret_cast<const uint32_t*>(codeDump + 6) == 0x65747942) {
      iatRef = findCallOrJmpPtr(
          textBase + FindDelphiCall(codeDump, static_cast<uint32_t>(codeSize)),
          true);
    } else {
      iatRef = findCallOrJmpPtr(textBase, true);
    }

    if (iatRef == 0) {
      Log(kLogInfo, "No IAT reference found via reference search");
      if (!guard_addrs_.empty()) {
        uint8_t site[6]{};
        RPM(guard_addrs_[0], site, 6);
        uintptr_t target = 0;
        if (site[0] == 0xE8 || site[0] == 0xE9) {
          target = *reinterpret_cast<const uint32_t*>(site + 1) +
                   guard_addrs_[0] + 5;
        } else if (site[1] == 0xE8 || site[1] == 0xE9) {
          target = *reinterpret_cast<const uint32_t*>(site + 2) +
                   guard_addrs_[0] + 6;
        } else {
          throw std::runtime_error("First guard addr is not call/jmp");
        }

        LogF(kLogInfo, "First guard addr %.8llX yielded API %.8llX",
             static_cast<unsigned long long>(guard_addrs_[0]),
             static_cast<unsigned long long>(target));
        iatRef = scanData(target, false);
      } else {
        throw std::runtime_error("Found no way to obtain IAT reference");
      }
    }
    LogF(kLogGood, "First IAT ref: %08llX",
         static_cast<unsigned long long>(iatRef));

    // The IATRef we obtained points somewhere into the IAT area. Now we need
    // to figure out the start of the table.
    uintptr_t result = 0;
    uintptr_t seeker = iatRef;
    // Read data such that the last word is the pointer at IATRef.
    std::vector<uintptr_t> iatData(kMaxIatSize / sizeof(uintptr_t));
    const uintptr_t readSize = iatData.size() * sizeof(uintptr_t);
    if (iatRef < readSize - sizeof(uintptr_t)) {
      throw std::runtime_error("IAT ref is too low");
    }
    RPM(iatRef - (readSize - sizeof(uintptr_t)), iatData.data(), readSize);
    int consecutive0 = 0;
    int index = static_cast<int>(iatData.size()) - 1;
    while (index >= 0) {
      if (iatData[static_cast<size_t>(index)] == 0) {
        ++consecutive0;
        if (consecutive0 > 64) {
          // Yes, there are legit executables that have almost 0x100 bytes
          // between their thunks.
          break;
        }
      } else if (dumper.IsAPIAddress(iatData[static_cast<size_t>(index)]) ||
                 (themida_v3_ &&
                  tm_sect_r_.Contains(iatData[static_cast<size_t>(index)]))) {
        result = seeker;
        consecutive0 = 0;
      } else {
        LogF(kLogInfo,
             "Ending IAT start search at %llX because pointer is %llX",
             static_cast<unsigned long long>(seeker),
             static_cast<unsigned long long>(
                 iatData[static_cast<size_t>(index)]));
        break;
      }

      --index;
      seeker -= sizeof(uintptr_t);
    }
    if (index == -1) {
      throw std::runtime_error("IAT too big");
    }
    if (result == 0) {
      throw std::runtime_error("IAT assertion failed");
    }
    return result;
  }
}

void ThemidaCommon::TraceImports(uintptr_t iat, Dumper& dumper) {
  ReportStatus("Tracing imports");
  std::array<uintptr_t, kMaxIatSize / sizeof(uintptr_t)> iatData{};
  RPM(iat, iatData.data(), sizeof(iatData));

  bool didSetExitProcess = false;
  uint32_t trashCounter = 0;
  for (size_t i = 0; i < iatData.size(); ++i) {
    if (tm_sect_r_.Contains(iatData[i])) {
      LogF(kLogInfo, "Trace: %.8llX [%.8llX]",
           static_cast<unsigned long long>(iatData[i]),
           static_cast<unsigned long long>(iat + i * sizeof(uintptr_t)));

      trashCounter = 0;

      CONTEXT context{};
      context.ContextFlags = CONTEXT_CONTROL;
      GetThreadContext(GetThread(current_thread_id_), &context);
#if defined(_WIN64)
      trace_start_sp_ = context.Rsp;
#else
      trace_start_sp_ = context.Esp;
#endif

      traced_api_ = 0;
      trace_in_vm_ = false;
      {
        Tracer tracer(process_.dwProcessId, current_thread_id_,
                      GetThread(current_thread_id_),
                      [this](Tracer& tracerRef, CONTEXT& contextRef) {
                        return TraceIsAtAPI(tracerRef, contextRef);
                      });
        // Normally a couple hundred suffice, but newer Themida v3 versions do
        // some export directory walking...
        tracer.Trace(iatData[i], 500000);

        if (trace_in_vm_) {
          if (!didSetExitProcess) {
            didSetExitProcess = true;
            // ExitProcess seems to be a special case that resolves to a VM
            // func - we assume there is only one such case.
            iatData[i] = reinterpret_cast<uintptr_t>(GetProcAddress(
                GetModuleHandleW(L"kernel32.dll"), "ExitProcess"));
            Log(kLogInfo, "Setting API to ExitProcess");
          } else {
            LogF(kLogFatal, "Unable to determine IAT address for %08llX",
                 static_cast<unsigned long long>(iat + i * sizeof(uintptr_t)));
          }
        } else if (traced_api_ != 0) {
          LogF(kLogInfo, "-> %llX",
               static_cast<unsigned long long>(traced_api_));
          if (traced_api_ < 0x10000 ||
              (traced_api_ >= image_base_ && traced_api_ < image_boundary_)) {
            Log(kLogInfo, "Discarding result & aborting IAT tracing");
            break;
          }
          iatData[i] = traced_api_;
        } else {
          Log(kLogFatal, "Tracing failed!");
        }
      }
    } else if (iatData[i] == 0 || !dumper.IsAPIAddress(iatData[i])) {
      ++trashCounter;
      if (trashCounter > 64) {
        break;
      }
    } else {
      trashCounter = 0;
    }
  }

  DWORD oldProtect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(iat),
                   sizeof(iatData), PAGE_READWRITE, &oldProtect);
  if (!WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(iat),
                          iatData.data(), sizeof(iatData), nullptr)) {
    throw std::runtime_error(
        Format("WriteProcessMemory failed (error %lu)", GetLastError()));
  }
}

uint32_t ThemidaCommon::FindDynamicTM(const std::string& pattern,
                                      uintptr_t offset) {
  if (offset != 0) {
    offset -= tm_sect_r_.address;
  }
  if (offset > tm_sect_r_.size) {
    return 0;
  }

  const uint32_t result =
      FindDynamic(pattern, tm_sect_ + offset, tm_sect_r_.size - offset);
  if (result > 0) {
    return result + static_cast<uint32_t>(tm_sect_r_.address + offset);
  }
  return 0;
}

uint32_t ThemidaCommon::FindStaticTM(const std::string& pattern,
                                     uintptr_t offset) {
  if (offset != 0) {
    offset -= tm_sect_r_.address;
  }
  if (offset > tm_sect_r_.size) {
    return 0;
  }

  const uint32_t result =
      FindStatic(pattern, tm_sect_ + offset, tm_sect_r_.size - offset);
  if (result > 0) {
    return result + static_cast<uint32_t>(tm_sect_r_.address + offset);
  }
  return 0;
}

}  // namespace magicmida
