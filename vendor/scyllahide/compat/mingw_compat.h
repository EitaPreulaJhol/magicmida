#pragma once

// Force-included for MinGW-w64 builds.  MSVC has these as real intrinsics /
// supports __pragma natively, so the header is a no-op there.
#ifndef _MSC_VER
#define __pragma(x)

#if !defined(__ASSEMBLER__) && defined(__cplusplus)
extern "C" inline void *_ReturnAddress(void)
{
    return __builtin_return_address(0);
}
#endif
#endif
