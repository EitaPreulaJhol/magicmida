    .intel_syntax noprefix
    .text

    .globl InstrumentationCallbackAsm
    .def InstrumentationCallbackAsm; .scl 2; .type 32; .endef
InstrumentationCallbackAsm:
    cmp eax, 0
    jne ReturnToCaller

    push rax
    push rcx
    push rbx
    push rbp
    push rdi
    push rsi
    push rsp
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    sub rsp, 0x20
    mov rcx, r10
    mov rdx, rax
    call InstrumentationCallback
    add rsp, 0x20

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop rsp
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    pop rcx
    add rsp, 8

ReturnToCaller:
    jmp r10

    .globl HookedKiUserExceptionDispatcher
    .def HookedKiUserExceptionDispatcher; .scl 2; .type 32; .endef
HookedKiUserExceptionDispatcher:
    # The trampoline calls us, so [rsp] is the return address and the
    # CONTEXT frame the original function expects is at [rsp + 8].
    lea rdx, [rsp + 8]
    xor ecx, ecx
    sub rsp, 0x28
    call ScyllaHandleKiUserExceptionDispatcher
    add rsp, 0x28
    ret
