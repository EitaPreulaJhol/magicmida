    .intel_syntax noprefix
    .text

    .globl _InstrumentationCallbackAsm
_InstrumentationCallbackAsm:
    cmp eax, 0
    jne ReturnToCaller

    pushad
    push eax
    push ecx
    call _ScyllaInstrumentationCallbackCdecl
    add esp, 8

    pop edi
    pop esi
    pop ebp
    add esp, 4
    pop ebx
    pop edx
    pop ecx
    add esp, 4

ReturnToCaller:
    jmp ecx

    .globl _HookedKiUserExceptionDispatcher
_HookedKiUserExceptionDispatcher:
    mov eax, [esp + 4]
    mov ecx, [esp]
    push eax
    push ecx
    call _ScyllaHandleKiUserExceptionDispatcher
    add esp, 8
    call _ScyllaGetOriginalKiUserExceptionDispatcher
    jmp eax

    .globl _HookedNativeCallInternal
_HookedNativeCallInternal:
    pushad
    push ecx
    push eax
    call _ScyllaHandleNativeCallInternalCdecl
    add esp, 8
    test eax, eax
    je NoHook

    popad
    add esp, 4
    push ecx
    push eax
    call _ScyllaHandleNativeCallInternalCdecl
    add esp, 8
    jmp eax

NoHook:
    popad
    call _ScyllaGetNativeCallContinue
    jmp eax
