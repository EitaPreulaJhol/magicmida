# Generates an RC file that embeds the 32-bit worker executable in the
# 64-bit magicmida.exe.
if(NOT DEFINED INPUT OR NOT DEFINED OUTPUT)
  message(FATAL_ERROR "GenerateWorkerRc.cmake requires INPUT and OUTPUT")
endif()

file(TO_NATIVE_PATH "${INPUT}" INPUT_NATIVE)
string(REPLACE "\\" "\\\\" INPUT_ESCAPED "${INPUT_NATIVE}")

file(WRITE "${OUTPUT}"
"#include <windows.h>\n"
"#define IDR_MAGICMIDA_WORKER 103\n"
"IDR_MAGICMIDA_WORKER RCDATA \"${INPUT_ESCAPED}\"\n")
