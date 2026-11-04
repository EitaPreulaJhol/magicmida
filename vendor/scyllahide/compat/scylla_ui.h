#pragma once

#include <windows.h>

// Headless replacement for the MessageBoxA calls in the ScyllaHide injector.
// The implementation lives in src/scyllahide.cpp and routes the text to the
// magicmida log instead of opening a modal dialog.
extern "C" int ScyllaHideMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption,
                                     UINT uType);
