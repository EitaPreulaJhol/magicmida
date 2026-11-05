cmake_minimum_required(VERSION 3.16)
project(magicmida VERSION 1.0.0 LANGUAGES C CXX RC)

if(NOT WIN32)
  message(FATAL_ERROR
      "Magicmida targets Windows only. Cross-compile with MinGW-w64 "
      "using one of the toolchain files in cmake/.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MAGICMIDA_32BIT_WORKER "" CACHE FILEPATH
    "32-bit worker executable to embed in the 64-bit build")

if(MSVC)
  enable_language(ASM_MASM)
else()
  enable_language(ASM)
endif()

# ---------------------------------------------------------------------------
# ScyllaHide (vendored, pinned snapshot)
# ---------------------------------------------------------------------------
set(SCYLLA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/scyllahide")
set(SCYLLA_INCLUDE_DIRS
    "${SCYLLA_DIR}"
    "${SCYLLA_DIR}/3rdparty"
    "${SCYLLA_DIR}/compat")

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(SCYLLA_HOOK_NAME HookLibraryx86)
  set(MAGICMIDA_BEAENGINE_OBJECT
      "${CMAKE_CURRENT_SOURCE_DIR}/vendor/beaengine/BeaEngineLibFPC.obj"
      CACHE FILEPATH "BeaEngine object file for 32-bit builds")
  set(MAGICMIDA_NTDLL_LIB "${SCYLLA_DIR}/3rdparty/ntdll/ntdll_x86.lib")
  set(SCYLLA_HOOK_NTDLL_LIB "${SCYLLA_DIR}/3rdparty/ntdll/ntdllp_x86.lib")
  if(MSVC)
    set(SCYLLA_HOOK_ASM "${SCYLLA_DIR}/HookLibrary/InstrumentationCallbackX86.asm")
  else()
    set(SCYLLA_HOOK_ASM "${SCYLLA_DIR}/HookLibrary/AsmGccX86.S")
  endif()
else()
  set(SCYLLA_HOOK_NAME HookLibraryx64)
  set(MAGICMIDA_BEAENGINE_OBJECT
      "${CMAKE_CURRENT_SOURCE_DIR}/vendor/beaengine/BeaEngineLib64.obj"
      CACHE FILEPATH "BeaEngine object file for 64-bit builds")
  set(MAGICMIDA_NTDLL_LIB "${SCYLLA_DIR}/3rdparty/ntdll/ntdll_x64.lib")
  set(SCYLLA_HOOK_NTDLL_LIB "${SCYLLA_DIR}/3rdparty/ntdll/ntdllp_x64.lib")
  if(MSVC)
    set(SCYLLA_HOOK_ASM "${SCYLLA_DIR}/HookLibrary/InstrumentationCallbackX64.asm")
  else()
    set(SCYLLA_HOOK_ASM "${SCYLLA_DIR}/HookLibrary/AsmGccX64.S")
  endif()
endif()

# The hook library is a private build artifact.  It is embedded into
# magicmida.exe as RCDATA and never installed or copied to bin/.
add_library(magicmida_scylla_hook SHARED
    "${SCYLLA_DIR}/HookLibrary/DllMain.cpp"
    "${SCYLLA_DIR}/HookLibrary/HookHelper.cpp"
    "${SCYLLA_DIR}/HookLibrary/HookedFunctions.cpp"
    "${SCYLLA_DIR}/Scylla/VersionPatch.cpp"
    "${SCYLLA_DIR}/HookLibrary/Export.def"
    "${SCYLLA_HOOK_ASM}")

target_include_directories(magicmida_scylla_hook PRIVATE ${SCYLLA_INCLUDE_DIRS})
target_compile_definitions(magicmida_scylla_hook PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601
    WIN32_NO_STATUS
    _CRT_SECURE_NO_WARNINGS)

if(MSVC)
  target_compile_options(magicmida_scylla_hook PRIVATE /W3)
  set_target_properties(magicmida_scylla_hook PROPERTIES
      MSVC_RUNTIME_LIBRARY "MultiThreaded")
  target_link_libraries(magicmida_scylla_hook PRIVATE
      "${SCYLLA_HOOK_NTDLL_LIB}"
      user32
      gdi32)
else()
  if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SCYLLA_HOOK_ENTRY "_DllMain@12")
  else()
    set(SCYLLA_HOOK_ENTRY "DllMain")
  endif()
  target_sources(magicmida_scylla_hook PRIVATE
      "${SCYLLA_DIR}/HookLibrary/HookLibraryCrt.cpp")
  target_compile_options(magicmida_scylla_hook PRIVATE
      -Wall -Wextra -Wno-unused-parameter -Wno-cast-function-type -fno-builtin
      -include "${SCYLLA_DIR}/compat/mingw_compat.h")
  target_link_options(magicmida_scylla_hook PRIVATE
      -nostdlib -Wl,--entry,${SCYLLA_HOOK_ENTRY} -static-libgcc)
  target_link_libraries(magicmida_scylla_hook PRIVATE
      gcc
      ntdll
      user32
      gdi32)
endif()

set_target_properties(magicmida_scylla_hook PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${SCYLLA_HOOK_NAME}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scylla"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scylla"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scylla")

# ---------------------------------------------------------------------------
# Core: shared by the GUI application
# ---------------------------------------------------------------------------
set(SCYLLA_DISTORM_SOURCES
    "${SCYLLA_DIR}/3rdparty/distorm/decoder.c"
    "${SCYLLA_DIR}/3rdparty/distorm/distorm.c"
    "${SCYLLA_DIR}/3rdparty/distorm/instructions.c"
    "${SCYLLA_DIR}/3rdparty/distorm/insts.c"
    "${SCYLLA_DIR}/3rdparty/distorm/mnemonics.c"
    "${SCYLLA_DIR}/3rdparty/distorm/operands.c"
    "${SCYLLA_DIR}/3rdparty/distorm/prefix.c"
    "${SCYLLA_DIR}/3rdparty/distorm/textdefs.c"
    "${SCYLLA_DIR}/3rdparty/distorm/wstring.c")

set(SCYLLA_INJECTOR_SOURCES
    "${SCYLLA_DIR}/InjectorCLI/ApplyHooking.cpp"
    "${SCYLLA_DIR}/InjectorCLI/DynamicMapping.cpp"
    "${SCYLLA_DIR}/InjectorCLI/RemoteHook.cpp"
    "${SCYLLA_DIR}/Scylla/Logger.cpp"
    "${SCYLLA_DIR}/Scylla/OsInfo.cpp"
    "${SCYLLA_DIR}/Scylla/Peb.cpp"
    "${SCYLLA_DIR}/Scylla/PebHider.cpp"
    "${SCYLLA_DIR}/Scylla/User32Loader.cpp"
    "${SCYLLA_DIR}/Scylla/Util.cpp"
    "${SCYLLA_DIR}/Scylla/VersionPatch.cpp")

set(MAGICMIDA_CORE_SOURCES
    src/antidump_fix.cpp
    src/common.cpp
    src/debugger_core.cpp
    src/disasm.cpp
    src/dumper.cpp
    src/onecore_uap.cpp
    src/patcher.cpp
    src/pe_info.cpp
    src/pe_report.cpp
    src/reloc_fix.cpp
    src/vm_entry.cpp
    src/scyllahide.cpp
    src/stream.cpp
    src/themida_common.cpp
    src/tracer.cpp
    ${SCYLLA_INJECTOR_SOURCES}
    ${SCYLLA_DISTORM_SOURCES})

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  list(APPEND MAGICMIDA_CORE_SOURCES src/themida32.cpp)
else()
  list(APPEND MAGICMIDA_CORE_SOURCES src/themida64.cpp)
endif()

add_library(magicmida_core OBJECT ${MAGICMIDA_CORE_SOURCES})
target_include_directories(magicmida_core PUBLIC src ${SCYLLA_INCLUDE_DIRS})
target_compile_definitions(magicmida_core PUBLIC
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601
    _CRT_SECURE_NO_WARNINGS
    SUPPORT_64BIT_OFFSET
    DISTORM_LIGHT
    "MAGICMIDA_VERSION=\"${PROJECT_VERSION}\"")

if(MSVC)
  target_compile_options(magicmida_core PRIVATE /W3)
  if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(WARNING
        "The 32-bit build uses a GCC-produced BeaEngine COFF object. If the "
        "MSVC linker rejects it, use the MinGW-w64 32-bit toolchain instead.")
  endif()
  target_link_libraries(magicmida_core PUBLIC
      "${MAGICMIDA_NTDLL_LIB}"
      psapi
      comdlg32
      user32
      gdi32
      advapi32
      shell32)
else()
  target_compile_options(magicmida_core PRIVATE
      -Wall -Wextra -Wno-unused-parameter -Wno-cast-function-type
      -include "${SCYLLA_DIR}/compat/mingw_compat.h")
  target_link_libraries(magicmida_core PUBLIC
      ntdll
      psapi
      comdlg32
      user32
      gdi32
      advapi32
      shell32)
endif()

# ---------------------------------------------------------------------------
# Application resources
# ---------------------------------------------------------------------------
file(TO_NATIVE_PATH
     "${CMAKE_CURRENT_SOURCE_DIR}/resources/magicmida.exe.manifest"
     MAGICMIDA_MANIFEST)
string(REPLACE "\\" "\\\\" MAGICMIDA_MANIFEST "${MAGICMIDA_MANIFEST}")

set(MAGICMIDA_FILE_DESCRIPTION "Magicmida")
set(MAGICMIDA_INTERNAL_NAME "magicmida")
set(MAGICMIDA_ORIGINAL_FILENAME "magicmida.exe")
configure_file(resources/magicmida.rc.in
               "${CMAKE_CURRENT_BINARY_DIR}/magicmida.rc" @ONLY)

if(CMAKE_CONFIGURATION_TYPES)
  set(SCYLLA_HOOK_RC "${CMAKE_CURRENT_BINARY_DIR}/scylla_hook_${CMAKE_CFG_INTDIR}.rc")
else()
  set(SCYLLA_HOOK_RC "${CMAKE_CURRENT_BINARY_DIR}/scylla_hook.rc")
endif()
add_custom_command(
    OUTPUT "${SCYLLA_HOOK_RC}"
    COMMAND ${CMAKE_COMMAND}
        -DINPUT=$<TARGET_FILE:magicmida_scylla_hook>
        -DOUTPUT=${SCYLLA_HOOK_RC}
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateScyllaHookRc.cmake"
    DEPENDS "$<TARGET_FILE:magicmida_scylla_hook>"
            magicmida_scylla_hook
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateScyllaHookRc.cmake"
    COMMENT "Embedding ScyllaHide hook library")
set_source_files_properties("${SCYLLA_HOOK_RC}" PROPERTIES GENERATED TRUE)

set(MAGICMIDA_WORKER_RC "")
if(CMAKE_SIZEOF_VOID_P EQUAL 8 AND MAGICMIDA_32BIT_WORKER)
  get_filename_component(MAGICMIDA_32BIT_WORKER_ABS
      "${MAGICMIDA_32BIT_WORKER}" ABSOLUTE
      BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  if(NOT EXISTS "${MAGICMIDA_32BIT_WORKER_ABS}")
    message(FATAL_ERROR
        "MAGICMIDA_32BIT_WORKER does not exist: ${MAGICMIDA_32BIT_WORKER_ABS}")
  endif()
  set(MAGICMIDA_WORKER_RC "${CMAKE_CURRENT_BINARY_DIR}/magicmida_worker.rc")
  add_custom_command(
      OUTPUT "${MAGICMIDA_WORKER_RC}"
      COMMAND ${CMAKE_COMMAND}
          "-DINPUT=${MAGICMIDA_32BIT_WORKER_ABS}"
          "-DOUTPUT=${MAGICMIDA_WORKER_RC}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateWorkerRc.cmake"
      DEPENDS "${MAGICMIDA_32BIT_WORKER_ABS}"
              "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateWorkerRc.cmake"
      COMMENT "Embedding the 32-bit worker")
  set_source_files_properties("${MAGICMIDA_WORKER_RC}"
      PROPERTIES GENERATED TRUE)
endif()

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  # Internal 32-bit worker.  It is embedded into the 64-bit executable and
  # is not a user-facing application.
  set(MAGICMIDA_APP_TARGET magicmida_worker)
  add_executable(${MAGICMIDA_APP_TARGET} WIN32
      src/gui_main.cpp
      "${CMAKE_CURRENT_BINARY_DIR}/magicmida.rc"
      "${SCYLLA_HOOK_RC}")
  target_compile_definitions(${MAGICMIDA_APP_TARGET} PRIVATE
      MAGICMIDA_WORKER_ONLY)
  set_target_properties(${MAGICMIDA_APP_TARGET} PROPERTIES
      OUTPUT_NAME "magicmida_worker"
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build/worker")
  foreach(config Debug Release RelWithDebInfo MinSizeRel)
    set_target_properties(${MAGICMIDA_APP_TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${config} "${CMAKE_SOURCE_DIR}/build/worker")
  endforeach()
else()
  # The distributed application: 64-bit GUI with the 32-bit worker embedded.
  set(MAGICMIDA_APP_TARGET magicmida)
  add_executable(${MAGICMIDA_APP_TARGET} WIN32
      src/gui_main.cpp
      "${CMAKE_CURRENT_BINARY_DIR}/magicmida.rc"
      "${SCYLLA_HOOK_RC}"
      ${MAGICMIDA_WORKER_RC})
  set_target_properties(${MAGICMIDA_APP_TARGET} PROPERTIES
      OUTPUT_NAME "magicmida"
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build")
  foreach(config Debug Release RelWithDebInfo MinSizeRel)
    set_target_properties(${MAGICMIDA_APP_TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${config} "${CMAKE_SOURCE_DIR}/build")
  endforeach()
  install(TARGETS magicmida RUNTIME DESTINATION .)
endif()

target_link_libraries(${MAGICMIDA_APP_TARGET} PRIVATE
    magicmida_core
    "${MAGICMIDA_BEAENGINE_OBJECT}")
add_dependencies(${MAGICMIDA_APP_TARGET} magicmida_scylla_hook)

if(MSVC)
  target_compile_options(${MAGICMIDA_APP_TARGET} PRIVATE /W3)
else()
  target_compile_options(${MAGICMIDA_APP_TARGET} PRIVATE
      -Wall -Wextra -Wno-unused-parameter -Wno-cast-function-type)
  target_link_options(${MAGICMIDA_APP_TARGET} PRIVATE
      -static -static-libgcc -static-libstdc++)
endif()
