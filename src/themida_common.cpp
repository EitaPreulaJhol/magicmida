// Magicmida - C++ port
// Shared Themida-unpacking logic (ported from ThemidaCommon.pas).
#include "themida_common.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>

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

  peSections_.assign(sections, sections + nt->FileHeader.NumberOfSections);

  if (peSections_.empty()) {
    throw std::runtime_error("The selected binary has no sections.");
  }

  if (nt->OptionalHeader.AddressOfEntryPoint <
      peSections_[0].VirtualAddress + peSections_[0].Misc.VirtualSize) {
    throw std::runtime_error(
        "The selected binary does not seem to be packed (entrypoint is in "
        ".text section).");
  }

  imageBoundary_ = nt->OptionalHeader.SizeOfImage + imageBase_;
  LogF(ltInfo, "Image boundary: %p", reinterpret_cast<void*>(imageBoundary_));

  majorLinkerVersion_ = nt->OptionalHeader.MajorLinkerVersion;
  LogF(ltInfo, "Image linker: %d.%d", majorLinkerVersion_,
       nt->OptionalHeader.MinorLinkerVersion);
}

void ThemidaCommon::CheckVirtualizedOEP(uintptr_t oep) {
  uint8_t code[16]{};
  if (!RPM(oep, code, sizeof(code)) || tmSectR_.Address == 0) {
    return;
  }

  uintptr_t target = 0;
  if (code[0] == 0xE9 || code[0] == 0xE8) {
    int32_t displacement = 0;
    std::memcpy(&displacement, code + 1, sizeof(displacement));
    target = static_cast<uintptr_t>(
        static_cast<int64_t>(oep) + 5 + displacement);
  } else if (code[0] == 0xEB) {
    target = static_cast<uintptr_t>(
        static_cast<int64_t>(oep) + 2 + static_cast<int8_t>(code[1]));
  } else if (code[0] == 0x68 && code[5] == 0xC3) {
    // push imm32; ret
    uint32_t immediate = 0;
    std::memcpy(&immediate, code + 1, sizeof(immediate));
    target = immediate;
  } else if (code[0] == 0xB8 && code[5] == 0xFF && code[6] == 0xE0) {
    // mov eax, imm32; jmp eax
    uint32_t immediate = 0;
    std::memcpy(&immediate, code + 1, sizeof(immediate));
    target = immediate;
  } else if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF &&
             code[11] == 0xE0) {
    // mov rax, imm64; jmp rax
    uint64_t immediate = 0;
    std::memcpy(&immediate, code + 2, sizeof(immediate));
    target = static_cast<uintptr_t>(immediate);
  } else {
    return;
  }

  if (!peSections_.empty()) {
    const uintptr_t textStart = imageBase_ + peSections_[0].VirtualAddress;
    const uintptr_t textEnd = textStart + peSections_[0].Misc.VirtualSize;
    if (target >= textStart && target < textEnd) {
      // A jump inside the application's code section is not the VM.
      return;
    }
  }

  if (target < tmSectR_.Address ||
      (imageBoundary_ != 0 && target >= imageBoundary_)) {
    return;
  }

  isVMOEP_ = true;
  LogF(ltInfo, "OEP is virtualized (!): %llX -> %llX",
       static_cast<unsigned long long>(oep),
       static_cast<unsigned long long>(target));
  Log(ltWarning,
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
      if (dis.VirtualAddr < textBase || dis.VirtualAddr >= textBase + codeSize) {
        break;
      }

      const int len = DisasmCheck(dis);

      if (*reinterpret_cast<const uint16_t*>(dis.EIP) == 0x15FF ||
          *reinterpret_cast<const uint16_t*>(dis.EIP) == 0x25FF) {
        LogF(ltInfo, "Found %08llX : %s",
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

        const uintptr_t result = findCallOrJmpPtr(dis.Instruction.AddrValue, false);
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
  };

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

  // For MSVC, the IAT often resides at imageBase + baseOfData. Other compilers
  // such as Delphi use a dedicated .idata section, but the IAT doesn't start
  // directly at the beginning, so some guesswork is needed.
  dataSectionIndex = 0;
  for (size_t i = 0; i < peSections_.size(); ++i) {
    if (baseOfData_ <
        peSections_[i].VirtualAddress + peSections_[i].Misc.VirtualSize) {
      dataSectionIndex = static_cast<int>(i);
      break;
    }
  }

  textBase = imageBase_ + peSections_[0].VirtualAddress;
  codeSize = baseOfData_ - peSections_[0].VirtualAddress;
  dataSize = peSections_[static_cast<size_t>(dataSectionIndex)].Misc.VirtualSize -
             (baseOfData_ -
              peSections_[static_cast<size_t>(dataSectionIndex)].VirtualAddress);
  LogF(ltInfo, "Text base: 0x%.8llX, code size: 0x%llX, data size: 0x%llX",
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
      iatRef = findGoAPICall(textBase +
                             FindGoBuildIdEnd(codeDump,
                                              static_cast<uint32_t>(codeSize)));
    } else if (!isVMOEP_) {
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
      Log(ltInfo, "No IAT reference found via reference search");
      if (!guardAddrs_.empty()) {
        uint8_t site[6]{};
        RPM(guardAddrs_[0], site, 6);
        uintptr_t target = 0;
        if (site[0] == 0xE8 || site[0] == 0xE9) {
          target = *reinterpret_cast<const uint32_t*>(site + 1) +
                   guardAddrs_[0] + 5;
        } else if (site[1] == 0xE8 || site[1] == 0xE9) {
          target = *reinterpret_cast<const uint32_t*>(site + 2) +
                   guardAddrs_[0] + 6;
        } else {
          throw std::runtime_error("First guard addr is not call/jmp");
        }

        LogF(ltInfo, "First guard addr %.8llX yielded API %.8llX",
             static_cast<unsigned long long>(guardAddrs_[0]),
             static_cast<unsigned long long>(target));
        iatRef = scanData(target, false);
      } else {
        throw std::runtime_error("Found no way to obtain IAT reference");
      }
    }
    LogF(ltGood, "First IAT ref: %08llX",
         static_cast<unsigned long long>(iatRef));

    // The IATRef we obtained points somewhere into the IAT area. Now we need
    // to figure out the start of the table.
    uintptr_t result = 0;
    uintptr_t seeker = iatRef;
    // Read data such that the last word is the pointer at IATRef.
    std::vector<uintptr_t> iatData(MAX_IAT_SIZE / sizeof(uintptr_t));
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
                 (themidaV3_ && tmSectR_.Contains(
                                    iatData[static_cast<size_t>(index)]))) {
        result = seeker;
        consecutive0 = 0;
      } else {
        LogF(ltInfo, "Ending IAT start search at %llX because pointer is %llX",
             static_cast<unsigned long long>(seeker),
             static_cast<unsigned long long>(iatData[static_cast<size_t>(index)]));
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
  std::array<uintptr_t, MAX_IAT_SIZE / sizeof(uintptr_t)> iatData{};
  RPM(iat, iatData.data(), sizeof(iatData));

  bool didSetExitProcess = false;
  uint32_t trashCounter = 0;
  for (size_t i = 0; i < iatData.size(); ++i) {
    if (tmSectR_.Contains(iatData[i])) {
      LogF(ltInfo, "Trace: %.8llX [%.8llX]",
           static_cast<unsigned long long>(iatData[i]),
           static_cast<unsigned long long>(iat + i * sizeof(uintptr_t)));

      trashCounter = 0;

      CONTEXT context{};
      context.ContextFlags = CONTEXT_CONTROL;
      GetThreadContext(GetThread(currentThreadId_), &context);
#if defined(_WIN64)
      traceStartSP_ = context.Rsp;
#else
      traceStartSP_ = context.Esp;
#endif

      tracedAPI_ = 0;
      traceInVM_ = false;
      {
        Tracer tracer(process_.dwProcessId, currentThreadId_,
                      GetThread(currentThreadId_),
                      [this](Tracer& tracerRef, CONTEXT& contextRef) {
                        return TraceIsAtAPI(tracerRef, contextRef);
                      });
        // Normally a couple hundred suffice, but newer Themida v3 versions do
        // some export directory walking...
        tracer.Trace(iatData[i], 500000);

        if (traceInVM_) {
          if (!didSetExitProcess) {
            didSetExitProcess = true;
            // ExitProcess seems to be a special case that resolves to a VM
            // func - we assume there is only one such case.
            iatData[i] = reinterpret_cast<uintptr_t>(GetProcAddress(
                GetModuleHandleW(L"kernel32.dll"), "ExitProcess"));
            Log(ltInfo, "Setting API to ExitProcess");
          } else {
            LogF(ltFatal, "Unable to determine IAT address for %08llX",
                 static_cast<unsigned long long>(
                     iat + i * sizeof(uintptr_t)));
          }
        } else if (tracedAPI_ != 0) {
          LogF(ltInfo, "-> %llX",
               static_cast<unsigned long long>(tracedAPI_));
          if (tracedAPI_ < 0x10000 ||
              (tracedAPI_ >= imageBase_ && tracedAPI_ < imageBoundary_)) {
            Log(ltInfo, "Discarding result & aborting IAT tracing");
            break;
          }
          iatData[i] = tracedAPI_;
        } else {
          Log(ltFatal, "Tracing failed!");
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
    offset -= tmSectR_.Address;
  }
  if (offset > tmSectR_.Size) {
    return 0;
  }

  const uint32_t result =
      FindDynamic(pattern, tmSect_ + offset, tmSectR_.Size - offset);
  if (result > 0) {
    return result + static_cast<uint32_t>(tmSectR_.Address + offset);
  }
  return 0;
}

uint32_t ThemidaCommon::FindStaticTM(const std::string& pattern,
                                     uintptr_t offset) {
  if (offset != 0) {
    offset -= tmSectR_.Address;
  }
  if (offset > tmSectR_.Size) {
    return 0;
  }

  const uint32_t result =
      FindStatic(pattern, tmSect_ + offset, tmSectR_.Size - offset);
  if (result > 0) {
    return result + static_cast<uint32_t>(tmSectR_.Address + offset);
  }
  return 0;
}

}  // namespace magicmida
