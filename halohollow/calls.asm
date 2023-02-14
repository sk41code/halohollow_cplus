.data
	systemCall WORD 000h
	syscallAddr QWORD 0h

.code
	

	GetSyscall proc
					mov systemCall, cx
					ret
	GetSyscall endp

	GetSyscallAddr proc
			mov syscallAddr, rcx
			ret
	GetSyscallAddr endp

	myNtGetContextThread proc
					mov r10, rcx
					mov ax, systemCall
					jmp	qword ptr syscallAddr
					ret
	myNtGetContextThread endp

	whatForeverMemory proc
					mov r10, rcx
					mov ax, systemCall
					jmp	qword ptr syscallAddr
					ret
	whatForeverMemory endp



end