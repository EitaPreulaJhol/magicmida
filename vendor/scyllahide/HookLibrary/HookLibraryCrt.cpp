#include <stddef.h>

// Minimal freestanding replacements for the C runtime routines used by the
// hook library.  The MinGW build links with -nostdlib so the hook DLL does not
// import msvcrt.dll: the payload is manually mapped into the target and the
// target is not guaranteed to have the MinGW CRT loaded at the same address.

extern "C" {

void *memcpy(void *dst, const void *src, size_t size)
{
    unsigned char *d = static_cast<unsigned char *>(dst);
    const unsigned char *s = static_cast<const unsigned char *>(src);
    while (size-- != 0)
        *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t size)
{
    unsigned char *d = static_cast<unsigned char *>(dst);
    const unsigned char *s = static_cast<const unsigned char *>(src);
    if (d < s || d >= s + size) {
        while (size-- != 0)
            *d++ = *s++;
    } else {
        d += size;
        s += size;
        while (size-- != 0)
            *--d = *--s;
    }
    return dst;
}

void *memset(void *dst, int value, size_t size)
{
    unsigned char *d = static_cast<unsigned char *>(dst);
    while (size-- != 0)
        *d++ = static_cast<unsigned char>(value);
    return dst;
}

int memcmp(const void *lhs, const void *rhs, size_t size)
{
    const unsigned char *a = static_cast<const unsigned char *>(lhs);
    const unsigned char *b = static_cast<const unsigned char *>(rhs);
    while (size-- != 0) {
        if (*a != *b)
            return static_cast<int>(*a) - static_cast<int>(*b);
        ++a;
        ++b;
    }
    return 0;
}

size_t strlen(const char *str)
{
    const char *p = str;
    while (*p != '\0')
        ++p;
    return static_cast<size_t>(p - str);
}

int strncmp(const char *lhs, const char *rhs, size_t size)
{
    while (size-- != 0) {
        const unsigned char a = static_cast<unsigned char>(*lhs++);
        const unsigned char b = static_cast<unsigned char>(*rhs++);
        if (a != b)
            return static_cast<int>(a) - static_cast<int>(b);
        if (a == '\0')
            return 0;
    }
    return 0;
}

size_t wcslen(const wchar_t *str)
{
    const wchar_t *p = str;
    while (*p != L'\0')
        ++p;
    return static_cast<size_t>(p - str);
}

wchar_t *wcscat(wchar_t *dst, const wchar_t *src)
{
    wchar_t *p = dst;
    while (*p != L'\0')
        ++p;
    while ((*p++ = *src++) != L'\0') {
    }
    return dst;
}

}  // extern "C"
