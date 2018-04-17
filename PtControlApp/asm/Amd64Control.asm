;   Windows Intel PT Driver
;   Filename: Amd64Control.asm
;	Description: Implement some control routine for the Hypervisor tests
;	Last revision: 04/06/2017
TITLE Intel Pt Control App AMD64 Assembler File


;Declare an external function
;EXTERN ExternalCFunc: PROC

.data

.code
;void _xsaves(void *mem, unsigned __int64 save_mask);
_xsaves PROC
	mov r8, rcx
	mov ecx, edx
	shr rdx, 020h
	xsaves qword ptr [r8]
	ret
_xsaves ENDP

;void MovToRdi(QWORD value)
MovToRdi PROC
   mov rdi, rcx
   xor rcx, rcx
   ret
MovToRdi ENDP

END