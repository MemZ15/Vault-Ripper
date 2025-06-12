;++
; LSTARHookDetect
; Copyright (c) 2017-2020, Aidan Khoury. All rights reserved.
;
; @file detect.asm
; @author Aidan Khoury (ajkhoury)
; @date 4/20/2020
;--

; detect.asm
PUBLIC FallbackHandler
PUBLIC PageFaultHookHandler
PUBLIC CVE_2018_1017

.code

FallbackHandler PROC
    iretq
FallbackHandler ENDP

PageFaultHookHandler PROC
    add rsp, 8               ; skip fault code on stack
    xchg qword ptr [rsp], rcx
    iretq
PageFaultHookHandler ENDP

CVE_2018_1017 PROC
        push    rbx                             ; backup rbx which is to be clobbered

        mov     ecx, 0C0000101h                 ; read original GS_BASE MSR
        rdmsr                                   ;
        push    rdx                             ; backup original GS_BASE MSR
        push    rax                             ;
        mov     ecx, 0C0000102h                 ; read original KERNEL_GS_BASE MSR
        rdmsr                                   ;
        push    rdx                             ; backup original KERNEL_GS_BASE MSR
        push    rax                             ;

        swapgs                                  ; swapgs to emulate coming from user mode

        xor     eax, eax                        ;
        xor     edx, edx                        ; set KERNEL_GS_BASE MSR to zero
        wrmsr                                   ;

        syscall                                 ; execute syscall instruction which executes swapgs immediately
        mov     rbx, rcx                        ; store real syscall handler address in rbx for now

        mov     ecx, 0C0000102h                 ;
        pop     rax                             ;
        pop     rdx                             ; restore original KERNEL_GS_BASE MSR
        wrmsr                                   ;
        mov     ecx, 0C0000101h                 ;
        pop     rax                             ;
        pop     rdx                             ; restore original GS_BASE MSR
        wrmsr                                   ;

        mov     rax, rbx                        ; return result in rax
        pop     rbx                             ; restore original rbx
        ret                                     ; return to caller
CVE_2018_1017 ENDP

END
