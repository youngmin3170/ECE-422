.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
push	$0xc105ed
mov	%esp, %ecx

push	$0x00000000
push	$0x646F6F66	
push	$0x6C6F6F63	
mov	%esp, %eax

push	%eax
push	%ecx
push	$0xacce55ed

call 	practice
add	$28, %esp

leave
ret
