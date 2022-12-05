/* See COPYRIGHT for copyright information. */

#ifndef JOS_KERN_TRAP_H
#define JOS_KERN_TRAP_H
#ifndef JOS_KERNEL
#error "This is a JOS kernel header; user programs should not #include it"
#endif

#include <inc/mmu.h>
#include <inc/trap.h>

/* The kernel's interrupt descriptor table */
extern struct Gatedesc idt[];
extern struct Pseudodesc idt_pd;

void trap_init(void);
void trap_init_percpu(void);
void print_regs(struct PushRegs *regs);
void print_trapframe(struct Trapframe *tf);
void page_fault_handler(struct Trapframe *);
void trap_handler(struct Trapframe *);
void backtrace(struct Trapframe *);

void fault0();
void fault3();
void fault13();
void fault14();
void fault32();//clock
void fault48();//syscall

#endif /* JOS_KERN_TRAP_H */
