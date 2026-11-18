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

std::string SafeString(const char* data, size_t max_length) {
  size_t length = 0;
  while (length < max_length && data[length] != '\0') {
    ++length;
  }
  return std::string(data, length);
}

uint32_t FindDelphiCall(const uint8_t* code_dump, uint32_t code_size) {
  // Delphi has type metadata at its .text base rather than code.
  uint32_t i = 0;
  uint32_t counter = 0;
  while (i + 6 < code_size) {
    if (*reinterpret_cast<const uint16_t*>(code_dump + i) == 0x25FF) {
      ++counter;
      if (counter == 3) {  // Skip the first two for good measure
        return i;
      }
    }
    ++i;
  }
  return 0;
}

uint32_t FindGoBuildIdEnd(const uint8_t* code_dump, uint32_t code_size) {
  // Go has "Go build ID" at the start of .text.
  for (uint32_t i = 0; i + 2 <= code_size; ++i) {
    if (*reinterpret_cast<const uint16_t*>(code_dump + i) == 0xFF20) {
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

  const auto read_stub = [&](uintptr_t address, VmStubInfo* info) -> bool {
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
  if (!read_stub(oep, &info)) {
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
      if (read_stub(target, &next)) {
        target = image_base_ + next.target_rva;
      }
    }
  }

  if (!pe_sections_.empty()) {
    const uintptr_t text_start = image_base_ + pe_sections_[0].VirtualAddress;
    const uintptr_t text_end = text_start + pe_sections_[0].Misc.VirtualSize;
    if (target >= text_start && target < text_end) {
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
  uintptr_t text_base = 0;
  uintptr_t code_size = 0;
  uintptr_t data_size = 0;
  int data_section_index = 0;
  uint8_t* code_dump = nullptr;
  uint32_t num_instr = 0;

  std::function<uintptr_t(uintptr_t, bool)> find_call_or_jmp_ptr =
      [&](uintptr_t address, bool ignore_method_boundary = false) -> uintptr_t {
    if (address < text_base || address >= text_base + code_size) {
      return 0;
    }

    DISASM dis{};
    dis.EIP = reinterpret_cast<uintptr_t>(code_dump) + address - text_base;
    dis.VirtualAddr = address;

    while ((num_instr < 200) || (ignore_method_boundary &&
                                 (dis.VirtualAddr < text_base + code_size))) {
      if (dis.VirtualAddr < text_base ||
          dis.VirtualAddr >= text_base + code_size) {
        break;
      }

      const int len = DisasmCheck(dis);

      if (*reinterpret_cast<const uint16_t*>(dis.EIP) == 0x15FF ||
          *reinterpret_cast<const uint16_t*>(dis.EIP) == 0x25FF) {
        LogF(kLogInfo, "Found %08llX : %s",
             static_cast<unsigned long long>(dis.VirtualAddr),
             SafeString(dis.CompleteInstr, sizeof(dis.CompleteInstr)).c_str());
        uintptr_t iat_pointer =
            static_cast<uintptr_t>(dis.Operand1.Memory.Displacement);
#if defined(_WIN64)
        iat_pointer += dis.VirtualAddr + 6;  // RIP-relative
#endif
        // Ensure we didn't stumble upon a pointer into .text.
        uintptr_t the_pointer = 0;
        if (!RPM(iat_pointer, &the_pointer, sizeof(the_pointer)) ||
            the_pointer > text_base + code_size) {
          return iat_pointer;
        }
      }

      if (*reinterpret_cast<const uint8_t*>(dis.EIP) == 0xE8 &&
          !ignore_method_boundary) {
        if (dis.Instruction.AddrValue < text_base ||
            dis.Instruction.AddrValue > text_base + code_size) {
          return 0;  // 32-bit: probably direct API call. Handled below.
        }

        const uintptr_t result =
            find_call_or_jmp_ptr(dis.Instruction.AddrValue, false);
        if (result != 0) {
          return result;
        }
      }

      if ((*reinterpret_cast<const uint8_t*>(dis.EIP) == 0xC3 ||
           *reinterpret_cast<const uint8_t*>(dis.EIP) == 0xC2) &&
          !ignore_method_boundary) {
        return 0;
      }

      ++num_instr;
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

  auto find_go_api_call = [&](uintptr_t address) -> uintptr_t {
    DISASM dis{};
    dis.EIP = reinterpret_cast<uintptr_t>(code_dump) + address - text_base;
    dis.VirtualAddr = address;

    while (dis.VirtualAddr < text_base + code_size) {
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
        uintptr_t iat_pointer =
            static_cast<uintptr_t>(dis.Operand2.Memory.Displacement);
#if defined(_WIN64)
        iat_pointer += dis.VirtualAddr + 7;  // RIP-relative
#endif
        uintptr_t the_pointer = 0;
        if (RPM(iat_pointer, &the_pointer, sizeof(the_pointer)) &&
            dumper.IsAPIAddress(the_pointer)) {
          return iat_pointer;
        }
      }

      ++num_instr;
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

  std::function<uintptr_t(uintptr_t, bool)> scan_data =
      [&](uintptr_t to_find, bool scan_code) -> uintptr_t {
    uintptr_t start_offset = 0;
    uintptr_t scan_size = 0;
    if (!scan_code) {
      start_offset = text_base + code_size;
      scan_size = data_size;
    } else {
      start_offset = text_base;
      scan_size = code_size;
    }

    std::vector<uint8_t> data_section(static_cast<size_t>(scan_size));
    if (!RPM(start_offset, data_section.data(), data_section.size())) {
      throw std::runtime_error("DetermineIATAddress.ScanData: RPM failed");
    }

    // We assume the table is machine-word aligned.
    const size_t count = data_section.size() / sizeof(uintptr_t);
    const auto* walker =
        reinterpret_cast<const uintptr_t*>(data_section.data());
    for (size_t index = 0; index < count; ++index) {
      if (walker[index] == to_find) {
        return start_offset + index * sizeof(uintptr_t);
      }
    }

    if (scan_code) {
      throw std::runtime_error("Unable to find API in section");
    }
    // Retry with first part of section in case of extreme merges (Themida V1).
    return scan_data(to_find, true);
  };

  // For MSVC, the IAT often resides at image_base + baseOfData. Other compilers
  // such as Delphi use a dedicated .idata section, but the IAT doesn't start
  // directly at the beginning, so some guesswork is needed.
  data_section_index = 0;
  for (size_t i = 0; i < pe_sections_.size(); ++i) {
    if (base_of_data_ <
        pe_sections_[i].VirtualAddress + pe_sections_[i].Misc.VirtualSize) {
      data_section_index = static_cast<int>(i);
      break;
    }
  }

  text_base = image_base_ + pe_sections_[0].VirtualAddress;
  code_size = base_of_data_ - pe_sections_[0].VirtualAddress;
  data_size =
      pe_sections_[static_cast<size_t>(data_section_index)].Misc.VirtualSize -
      (base_of_data_ -
       pe_sections_[static_cast<size_t>(data_section_index)].VirtualAddress);
  LogF(kLogInfo, "Text base: 0x%.8llX, code size: 0x%llX, data size: 0x%llX",
       static_cast<unsigned long long>(text_base),
       static_cast<unsigned long long>(code_size),
       static_cast<unsigned long long>(data_size));
  num_instr = 0;

  // 16 bytes of zero padding let the decoder safely read a full instruction
  // at the end of the code section (matching the original's behaviour).
  std::vector<uint8_t> code_dump_storage(static_cast<size_t>(code_size) + 16,
                                         0);
  code_dump = code_dump_storage.data();
  {
    if (!RPM(text_base, code_dump, code_size)) {
      throw std::runtime_error("DetermineIATAddress: RPM failed");
    }

    uintptr_t iat_ref = 0;
    if (*reinterpret_cast<const uint32_t*>(code_dump) == 0x6F4720FF) {
      iat_ref = find_go_api_call(
          text_base +
          FindGoBuildIdEnd(code_dump, static_cast<uint32_t>(code_size)));
    } else if (!is_vm_oep_) {
      iat_ref = find_call_or_jmp_ptr(oep, false);
    } else if (*reinterpret_cast<const uint32_t*>(
                   code_dump + (sizeof(void*) == 4 ? 6 : 10)) == 0x6C6F6F42 ||
               *reinterpret_cast<const uint32_t*>(code_dump + 6) ==
                   0x65747942) {
      iat_ref = find_call_or_jmp_ptr(
          text_base +
              FindDelphiCall(code_dump, static_cast<uint32_t>(code_size)),
          true);
    } else {
      iat_ref = find_call_or_jmp_ptr(text_base, true);
    }

    if (iat_ref == 0) {
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
        iat_ref = scan_data(target, false);
      } else {
        throw std::runtime_error("Found no way to obtain IAT reference");
      }
    }
    LogF(kLogGood, "First IAT ref: %08llX",
         static_cast<unsigned long long>(iat_ref));

    // The IATRef we obtained points somewhere into the IAT area. Now we need
    // to figure out the start of the table.
    uintptr_t result = 0;
    uintptr_t seeker = iat_ref;
    // Read data such that the last word is the pointer at IATRef.
    std::vector<uintptr_t> iat_data(kMaxIatSize / sizeof(uintptr_t));
    const uintptr_t read_size = iat_data.size() * sizeof(uintptr_t);
    if (iat_ref < read_size - sizeof(uintptr_t)) {
      throw std::runtime_error("IAT ref is too low");
    }
    RPM(iat_ref - (read_size - sizeof(uintptr_t)), iat_data.data(), read_size);
    int consecutive0 = 0;
    int index = static_cast<int>(iat_data.size()) - 1;
    while (index >= 0) {
      if (iat_data[static_cast<size_t>(index)] == 0) {
        ++consecutive0;
        if (consecutive0 > 64) {
          // Yes, there are legit executables that have almost 0x100 bytes
          // between their thunks.
          break;
        }
      } else if (dumper.IsAPIAddress(iat_data[static_cast<size_t>(index)]) ||
                 (themida_v3_ &&
                  tm_sect_r_.Contains(iat_data[static_cast<size_t>(index)]))) {
        result = seeker;
        consecutive0 = 0;
      } else {
        LogF(kLogInfo,
             "Ending IAT start search at %llX because pointer is %llX",
             static_cast<unsigned long long>(seeker),
             static_cast<unsigned long long>(
                 iat_data[static_cast<size_t>(index)]));
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
  std::array<uintptr_t, kMaxIatSize / sizeof(uintptr_t)> iat_data{};
  RPM(iat, iat_data.data(), sizeof(iat_data));

  bool did_set_exit_process = false;
  uint32_t trash_counter = 0;
  for (size_t i = 0; i < iat_data.size(); ++i) {
    if (tm_sect_r_.Contains(iat_data[i])) {
      LogF(kLogInfo, "Trace: %.8llX [%.8llX]",
           static_cast<unsigned long long>(iat_data[i]),
           static_cast<unsigned long long>(iat + i * sizeof(uintptr_t)));

      trash_counter = 0;

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
                      [this](Tracer& tracer_ref, CONTEXT& context_ref) {
                        return TraceIsAtAPI(tracer_ref, context_ref);
                      });
        // Normally a couple hundred suffice, but newer Themida v3 versions do
        // some export directory walking...
        tracer.Trace(iat_data[i], 500000);

        if (trace_in_vm_) {
          if (!did_set_exit_process) {
            did_set_exit_process = true;
            // ExitProcess seems to be a special case that resolves to a VM
            // func - we assume there is only one such case.
            iat_data[i] = reinterpret_cast<uintptr_t>(GetProcAddress(
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
          iat_data[i] = traced_api_;
        } else {
          Log(kLogFatal, "Tracing failed!");
        }
      }
    } else if (iat_data[i] == 0 || !dumper.IsAPIAddress(iat_data[i])) {
      ++trash_counter;
      if (trash_counter > 64) {
        break;
      }
    } else {
      trash_counter = 0;
    }
  }

  DWORD old_protect = 0;
  VirtualProtectEx(process_.hProcess, reinterpret_cast<void*>(iat),
                   sizeof(iat_data), PAGE_READWRITE, &old_protect);
  if (!WriteProcessMemory(process_.hProcess, reinterpret_cast<void*>(iat),
                          iat_data.data(), sizeof(iat_data), nullptr)) {
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
