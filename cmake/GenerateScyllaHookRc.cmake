# Generates an RC file that embeds the freshly built ScyllaHide hook DLL.
#
# INPUT  - absolute path to HookLibrary*.dll
# OUTPUT - generated .rc file
if(NOT DEFINED INPUT OR NOT DEFINED OUTPUT)
  message(FATAL_ERROR "GenerateScyllaHookRc.cmake requires INPUT and OUTPUT")
endif()

file(TO_NATIVE_PATH "${INPUT}" INPUT_NATIVE)
string(REPLACE "\\" "\\\\" INPUT_ESCAPED "${INPUT_NATIVE}")

file(WRITE "${OUTPUT}"
"#include <windows.h>\n"
"#define IDR_SCYLLA_HOOK_DLL 102\n"
"IDR_SCYLLA_HOOK_DLL RCDATA \"${INPUT_ESCAPED}\"\n")
