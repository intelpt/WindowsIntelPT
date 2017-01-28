;   Windows Intel PT Driver
;   Filename: Amd64XSave.asm
;	Description: Implement the support for the Supervisor XSAVE routines
;	Last revision: 01/25/2017
TITLE Windows Pt Driver AMD64 Assembler File


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


END