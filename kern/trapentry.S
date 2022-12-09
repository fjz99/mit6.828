/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>



###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
//通过汇编+宏来完成代码生成，这样编译之后的c的函数指针刚好指向这里
TRAPHANDLER_NOEC(fault0,0)
TRAPHANDLER_NOEC(fault3,3)
TRAPHANDLER(fault13,13)
TRAPHANDLER(fault14,14)

TRAPHANDLER_NOEC(fault48,48)
TRAPHANDLER_NOEC(fault32,IRQ_OFFSET+IRQ_TIMER)//clock

/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:
	//注意push stack传递参数的顺序和push的顺序相反
	pushl %ds //pushl似乎是32位的
	pushl %es
	pushal
	mov $(GD_KD), %eax //ds和es的修改只能借助于eax间接完成
	mov %eax, %ds 
	mov %eax, %es 

	//上面只是处理了结构体的内容，但是我们传递的参数是指针
	pushl %esp //push esp即可传递指针
	cli //关中断
	call trap
