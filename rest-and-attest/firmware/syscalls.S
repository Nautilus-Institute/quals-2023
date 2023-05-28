.text
.global _read_syscall
_read_syscall:
	mov $0, %rax
	syscall
	ret

.global _write_syscall
_write_syscall:
	mov $1, %rax
	syscall
	ret

.global _recvmsg_syscall
_recvmsg_syscall:
	mov $47, %rax
	syscall
	ret

.global _get_pc
_get_pc:
    movq (%rsp), %rax
    ret

