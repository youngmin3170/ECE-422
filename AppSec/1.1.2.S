.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here

push	$0xc001f00d #mp
push 	$0xc105ed #sec
push 	$0xacce55ed #app

call 	practice
add 	$12, %esp # clean up

leave
ret
