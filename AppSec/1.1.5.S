.section .data
str:
.asciz	"/bin/sh"

.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here
mov	$0xb, %eax	#sys_execve

push	$0x00000000
push	$str		# "/bin/sh"

mov	$str, %ebx
mov	%esp, %ecx
xor	%edx, %edx

int	$0x80

leave
ret
