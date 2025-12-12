.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here

push	$0xc001f00d	#mp
mov	%esp, %eax
push	%eax		#push pointer to stack
push	$0xc105ed	#sec
push	$0xacce55ed	#app

call 	practice	#call practice
add	$16, %esp	#clean up

leave
ret
