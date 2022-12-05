#include <inc/mmu.h>
#include <inc/memlayout.h>

// Page fault upcall entrypoint.

// This is where we ask the kernel to redirect us to whenever we cause
// a page fault in user space (see the call to sys_set_pgfault_handler
// in pgfault.c).
//
// When a page fault actually occurs, the kernel switches our ESP to
// point to the user exception stack if we're not already on the user
// exception stack, and then it pushes a UTrapframe onto our user
// exception stack:
//
//	trap-time esp
//	trap-time eflags
//	trap-time eip
//	utf_regs.reg_eax
//	...
//	utf_regs.reg_esi
//	utf_regs.reg_edi
//	utf_err (error code)
//	utf_fault_va            <-- %esp
//
// If this is a recursive fault, the kernel will reserve for us a
// blank word above the trap-time esp for scratch work when we unwind
// the recursive call.
//
// We then have call up to the appropriate page fault handler in C
// code, pointed to by the global variable '_pgfault_handler'.

.text
.globl _pgfault_upcall
_pgfault_upcall:
	// Call the C page fault handler.
	// 这里push的是内核栈的esp，仅仅是为了引入指针，就可以访问UTrapframe结构体了;esp指向的是刚刚好的结构体起始位置
	pushl %esp			// function argument: pointer to UTF
	movl _pgfault_handler, %eax
	call *%eax
	//栈顶减小，排除UTrapframe的结构体指针
	addl $4, %esp			// pop function argument

	//到这里，调用_pgfault_handler函数引入的stack push，都已经消除了
	
	// Now the C page fault handler has returned and you must return
	// to the trap time state.
	// Push trap-time %eip onto the trap-time stack.
	//
	// Explanation:
	//   We must prepare the trap-time stack for our eventual return to
	//   re-execute the instruction that faulted.
	//   Unfortunately, we can't return directly from the exception stack:
	//   We can't call 'jmp', since that requires that we load the address
	//   into a register, and all registers must have their trap-time
	//   values after the return.
	//   We can't call 'ret' from the exception stack either, since if we
	//   did, %esp would have the wrong value. 因为ret会读取栈顶的eip！此时就还是使用异常栈了！
	//   So instead, we push the trap-time %eip onto the *trap-time* stack!
	//   Below we'll switch to that stack and call 'ret', which will
	//   restore %eip to its pre-fault value.
	//
	//   In the case of a recursive fault on the exception stack,
	//   note that the word we're pushing now will fit in the
	//   blank word that the kernel reserved for us.
	//   为什么需要reserve这个word：方便push eip，当递归调用handler的时候，返回上次的eip的时候，
	//   要先切换为旧的esp、ebp，此时esp指向的是UTrapframe结构体的最低的一个word
	//
	// Throughout the remaining code, think carefully about what
	// registers are available for intermediate calculations.  You
	// may find that you have to rearrange your code in non-obvious
	// ways as registers become unavailable as scratch space.
	//
	// LAB 4: Your code here.
	// 从UTrapframe结构体中根据偏移量即可获得发生异常时的eip，esp，ss等
	// 这里也能看出必须有空洞，否则就会破坏存储的寄存器的值，而且通过空洞也能消除if
	movl $10,%ebx
	movl (%esp,%ebx,4),%eax //eip
	movl $12,%ebx
	//push,注意要push到esp的值的-1位置，否则会覆盖
	subl $4,(%esp,%ebx,4) //先把esp的值减4，空出一个eip的位置
	movl (%esp,%ebx,4),%edi //得到esp的值
	//把eip放到esp中
	movl %eax,(%edi) 

	// Restore the trap-time registers.  After you do this, you
	// can no longer modify any general-purpose registers.
	// LAB 4: Your code here.
	// FIXME ??
	addl $8, %esp
	popal //恢复所有通用寄存器,并且自动修改esp

	// Restore eflags from the stack.  After you do this, you can
	// no longer use arithmetic operations or anything else that
	// modifies eflags.
	// LAB 4: Your code here.
	addl $4, %esp
	popf

	// Switch back to the adjusted trap-time stack.
	// LAB 4: Your code here.
	popl %esp

	// Return to re-execute the instruction that faulted.
	// LAB 4: Your code here.
	ret
