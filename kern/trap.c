#include <inc/assert.h>
#include <inc/mmu.h>
#include <inc/x86.h>
#include <kern/console.h>
#include <kern/env.h>
#include <kern/kdebug.h>
#include <kern/monitor.h>
#include <kern/pmap.h>
#include <kern/sched.h>
#include <kern/spinlock.h>
#include <kern/syscall.h>
#include <kern/trap.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = {{0}};
struct Pseudodesc idt_pd = {sizeof(idt) - 1, (uint32_t)idt};

static const char *trapname(int trapno) {
  static const char *const excnames[] = {"Divide error",
                                         "Debug",
                                         "Non-Maskable Interrupt",
                                         "Breakpoint",
                                         "Overflow",
                                         "BOUND Range Exceeded",
                                         "Invalid Opcode",
                                         "Device Not Available",
                                         "Double Fault",
                                         "Coprocessor Segment Overrun",
                                         "Invalid TSS",
                                         "Segment Not Present",
                                         "Stack Fault",
                                         "General Protection",
                                         "Page Fault",
                                         "(unknown trap)",
                                         "x87 FPU Floating-Point Error",
                                         "Alignment Check",
                                         "Machine-Check",
                                         "SIMD Floating-Point Exception"};

  if (trapno < ARRAY_SIZE(excnames)) return excnames[trapno];
  if (trapno == T_SYSCALL) return "System call";
  return "(unknown trap)";
}

void trap_init(void) {
  extern struct Segdesc gdt[];

  // LAB 3: Your code here.
  // 初始化成中断门，此时就会自动关中断了！
  SETGATE(idt[T_DIVIDE], false, GD_KT, fault0, 0);
  SETGATE(idt[T_BRKPT], false, GD_KT, fault3, 3);
  SETGATE(idt[T_GPFLT], false, GD_KT, fault13, 0);
  SETGATE(idt[T_PGFLT], false, GD_KT, fault14, 0);
  SETGATE(idt[T_SYSCALL], false, GD_KT, fault48, 3);
  SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], false, GD_KT, fault32, 0);
  SETGATE(idt[IRQ_OFFSET + IRQ_KBD], false, GD_KT, fault33, 0);
  SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL], false, GD_KT, fault36, 0);

  // Per-CPU setup
  trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void trap_init_percpu(void) {
  // The example code here sets up the Task State Segment (TSS) and
  // the TSS descriptor for CPU 0. But it is incorrect if we are
  // running on other CPUs because each CPU has its own kernel stack.
  // Fix the code so that it works for all CPUs.
  //
  // Hints:
  //   - The macro "thiscpu" always refers to the current CPU's
  //     struct CpuInfo;
  //   - The ID of the current CPU is given by cpunum() or
  //     thiscpu->cpu_id;
  //   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
  //     rather than the global "ts" variable;
  //   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
  //   - You mapped the per-CPU kernel stacks in mem_init_mp()
  //   - Initialize cpu_ts.ts_iomb to prevent unauthorized environments
  //     from doing IO (0 is not the correct value!)
  //
  // ltr sets a 'busy' flag in the TSS selector, so if you
  // accidentally load the same TSS on more than one CPU, you'll
  // get a triple fault.  If you set up an individual CPU's TSS
  // wrong, you may not get a fault until you try to return from
  // user space on that CPU.
  //
  // LAB 4: Your code here:
  // cprintf("init cpu %d\n", thiscpu->cpu_id);
  thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - (KSTKSIZE + KSTKSIZE) * thiscpu->cpu_id;
  thiscpu->cpu_ts.ts_ss0 = GD_KD;
  thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);
  gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id] = SEG16(
      STS_T32A, (uint32_t)(&thiscpu->cpu_ts), sizeof(struct Taskstate) - 1, 0);
  gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id].sd_s = 0;
  ltr(GD_TSS0 + (thiscpu->cpu_id << 3));

  // Setup a TSS so that we get the right stack
  // when we trap to the kernel.
  // ts.ts_esp0 = KSTACKTOP;
  // ts.ts_ss0 = GD_KD;
  // ts.ts_iomb = sizeof(struct Taskstate);

  // Initialize the TSS slot of the gdt.
  // gdt[GD_TSS0 >> 3] =
  //     SEG16(STS_T32A, (uint32_t)(&ts), sizeof(struct Taskstate) - 1, 0);
  // gdt[GD_TSS0 >> 3].sd_s = 0;

  // Load the TSS selector (like other segment selectors, the
  // bottom three bits are special; we leave them 0)
  // ltr(GD_TSS0);

  // Load the IDT
  lidt(&idt_pd);
}

void print_trapframe(struct Trapframe *tf) {
  cprintf("TRAP frame at %p from CPU %d\n", tf, thiscpu->cpu_id);
  print_regs(&tf->tf_regs);
  cprintf("  es   0x----%04x\n", tf->tf_es);
  cprintf("  ds   0x----%04x\n", tf->tf_ds);
  cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
  // If this trap was a page fault that just happened
  // (so %cr2 is meaningful), print the faulting linear address.
  if (tf == last_tf && tf->tf_trapno == T_PGFLT)
    cprintf("  cr2  0x%08x\n", rcr2());
  cprintf("  err  0x%08x", tf->tf_err);
  // For page faults, print decoded fault error code:
  // U/K=fault occurred in user/kernel mode
  // W/R=a write/read caused the fault
  // PR=a protection violation caused the fault (NP=page not present).
  if (tf->tf_trapno == T_PGFLT)
    cprintf(" [%s, %s, %s]\n", tf->tf_err & 4 ? "user" : "kernel",
            tf->tf_err & 2 ? "write" : "read",
            tf->tf_err & 1 ? "protection" : "not-present");
  else
    cprintf("\n");
  cprintf("  eip  0x%08x\n", tf->tf_eip);
  cprintf("  cs   0x----%04x\n", tf->tf_cs);
  cprintf("  flag 0x%08x\n", tf->tf_eflags);
  if ((tf->tf_cs & 3) != 0) {
    cprintf("  esp  0x%08x\n", tf->tf_esp);
    cprintf("  ss   0x----%04x\n", tf->tf_ss);
  }
}

void print_regs(struct PushRegs *regs) {
  cprintf("  edi  0x%08x\n", regs->reg_edi);
  cprintf("  esi  0x%08x\n", regs->reg_esi);
  cprintf("  ebp  0x%08x\n", regs->reg_ebp);
  cprintf("  oesp 0x%08x\n", regs->reg_oesp);
  cprintf("  ebx  0x%08x\n", regs->reg_ebx);
  cprintf("  edx  0x%08x\n", regs->reg_edx);
  cprintf("  ecx  0x%08x\n", regs->reg_ecx);
  cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void abort_env(struct Trapframe *tf) {
  debug("Abort Env %08x due to %s Exception/Interrput\n", curenv->env_id,
        trapname(tf->tf_trapno));
  print_trapframe(tf);
  env_destroy(curenv);
}

static void tick(struct Trapframe *tf) {
  // debug("CPU %d Env %08x Get tick, force reschedule\n", cpunum(),
  // curenv ? curenv->env_id : 0);
  lapic_eoi();  // 别忘了加这个，否则中断触发一次之后就无了
  sched_yield();
}

static void trap_dispatch(struct Trapframe *tf) {
  // Handle processor exceptions.
  // LAB 3: Your code here.

  // Handle keyboard and serial interrupts.
  // LAB 5: Your code here.

  switch (tf->tf_trapno) {
    case T_DIVIDE:
    case T_GPFLT:
      abort_env(tf);
      return;
    case T_BRKPT:
      trap_handler(tf);
      return;
    case T_PGFLT:
      page_fault_handler(tf);
      return;
    case T_SYSCALL: {
      // int32_t rt = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx,
      //                      tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx,
      //                      tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
      // debug("SysCall rt %08x\n", rt);
      // 直接通过这个设置返回值即可，因为eax存放在栈上，会再次恢复的
      tf->tf_regs.reg_eax = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx,
                                    tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx,
                                    tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
      return;
    }
    case IRQ_OFFSET + IRQ_TIMER:
      tick(tf);
      return;
    case IRQ_OFFSET + IRQ_KBD:
      //响应键盘中断，这里把数据存放到了console的buffer中，但是这是内核态的console buf，不是用户态的
      //用户态下，会通过syscall来读取这个buf，从而实现getchar()函数
      kbd_intr(); 
      return;
    case IRQ_OFFSET + IRQ_SERIAL: // 似乎是串口数据
      serial_intr();
      return;
    default:
      // TODO trap没有被处理
      break;
  }

  // Handle spurious interrupts
  // The hardware sometimes raises these because of noise on the
  // IRQ line or other reasons. We don't care.
  if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
    cprintf("Spurious interrupt on irq 7\n");
    print_trapframe(tf);
    return;
  }

  // Handle clock interrupts. Don't forget to acknowledge the
  // interrupt using lapic_eoi() before calling the scheduler!
  // LAB 4: Your code here.

  // Unexpected trap: The user process or the kernel has a bug.
  print_trapframe(tf);
  if (tf->tf_cs == GD_KT)
    panic("unhandled trap in kernel");
  else {
    env_destroy(curenv);
    return;
  }
}

void trap(struct Trapframe *tf) {
  // debug("get trap %d ,Env %08x, eip %08x\n", tf->tf_trapno, curenv->env_id,
  // tf->tf_eip);

  // The environment may have set DF and some versions
  // of GCC rely on DF being clear
  asm volatile("cld" ::: "cc");

  // Halt the CPU if some other CPU has called panic()
  extern char *panicstr;
  if (panicstr) asm volatile("hlt");

  // Re-acqurie the big kernel lock if we were halted in
  // sched_yield()
  if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED) lock_kernel();

  // Check that interrupts are disabled.  If this assertion
  // fails, DO NOT be tempted to fix it by inserting a "cli" in
  // the interrupt path.

  // cprintf("Incoming TRAP frame at %p\n", tf);
  if ((tf->tf_cs & 3) == 0 && (read_eflags() & FL_IF)) {
    panic("int enable in kernel mode");
  }

  if ((tf->tf_cs & 3) == 3) {
    // Trapped from user mode.
    // Acquire the big kernel lock before doing any
    // serious kernel work.
    // LAB 4: Your code here.
    lock_kernel();

    assert(curenv);

    // Garbage collect if current enviroment is a zombie
    if (curenv->env_status == ENV_DYING) {
      env_free(curenv);
      curenv = NULL;
      sched_yield();
    }

    // Copy trap frame (which is currently on the stack)
    // into 'curenv->env_tf', so that running the environment
    // will restart at the trap point.
    curenv->env_tf = *tf;
    // The trapframe on the stack should be ignored from here on.
    tf = &curenv->env_tf;
  }

  // Record that tf is the last real trapframe so
  // print_trapframe can print some additional information.
  last_tf = tf;

  // Dispatch based on what type of trap occurred
  // 如果正常恢复了，就会执行后面的代码，恢复进程执行
  trap_dispatch(tf);

  // Return to the current environment, which should be running.
  // assert(curenv && curenv->env_status == ENV_RUNNING);
  // env_run(curenv);

  // 返回进程执行，如果当前进程被kill了，那就重新调度
  if (curenv != NULL && curenv->env_status == ENV_RUNNING)
    env_run(curenv);
  else
    sched_yield();
}

void page_fault_handler(struct Trapframe *tf) {
  uint32_t fault_va;

  // Read processor's CR2 register to find the faulting address
  fault_va = rcr2();

  // Handle kernel-mode page faults.

  // LAB 3: Your code here.
  // 注意这里必须处理，否则就会导致handler正常返回，然后就指令重试，然后就无限page
  // fault。。
  if ((tf->tf_cs & 3) == 0) {
    // _backtrace();
    panic("page fault in kernel mode for va %08x, eip=%08x", fault_va,
          tf->tf_eip);
  }

  // We've already handled kernel-mode exceptions, so if we get here,
  // the page fault happened in user mode.

  // Call the environment's page fault upcall, if one exists.  Set up a
  // page fault stack frame on the user exception stack (below
  // UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
  //
  // The page fault upcall might cause another page fault, in which case
  // we branch to the page fault upcall recursively, pushing another
  // page fault stack frame on top of the user exception stack.
  //
  // It is convenient for our code which returns from a page fault
  // (lib/pfentry.S) to have one word of scratch space at the top of the
  // trap-time stack; it allows us to more easily restore the eip/esp. In
  // the non-recursive case, we don't have to worry about this because
  // the top of the regular user stack is free.  In the recursive case,
  // this means we have to leave an extra word between the current top of
  // the exception stack and the new stack frame because the exception
  // stack _is_ the trap-time stack.
  // 如果有递归异常的话，两个栈帧之间间隔一个空白word，即存储ebp
  //
  // If there's no page fault upcall, the environment didn't allocate a
  // page for its exception stack or can't write to it, or the exception
  // stack overflows, then destroy the environment that caused the fault.
  // Note that the grade script assumes you will first check for the page
  // fault upcall and print the "user fault va" message below if there is
  // none.  The remaining three checks can be combined into a single test.
  //
  // Hints:
  //   user_mem_assert() and env_run() are useful here.
  //   调用env_run() 才是进入用户态
  //   To change what the user environment runs, modify 'curenv->env_tf'
  //   (the 'tf' variable points at 'curenv->env_tf').
  // LAB 4: Your code here.
  cprintf("[%08x] user fault va %08x ip %08x\n", curenv->env_id, fault_va,
          tf->tf_eip);

  if (curenv->env_pgfault_upcall) {
    // 异常栈已经在用户函数中被分配了
    // 检查异常栈是否溢出
    uintptr_t esp = tf->tf_esp;

    // 压入UTrapframe结构
    struct UTrapframe frame = {fault_va,   tf->tf_err,    tf->tf_regs,
                               tf->tf_eip, tf->tf_eflags, tf->tf_esp};
    uint32_t *base = (uint32_t *)UXSTACKTOP;
    if (esp >= UXSTACKTOP - PGSIZE && esp < UXSTACKTOP) {
      // 如果是嵌套异常，那么先压入一个word
      base = (uint32_t *)esp;
      base--;  // 指向刚好最后一个位置
      user_mem_assert(curenv, base, 4, PTE_P | PTE_W | PTE_U);
      *base = 0;
    }
    base = base - sizeof(struct UTrapframe) / 4;
    // cprintf("UTrapframe size %d stack esp %08x\n", sizeof(struct UTrapframe),
    //         base);

    // 检查下异常栈，保证安全
    user_mem_assert(curenv, base, sizeof(struct UTrapframe),
                    PTE_P | PTE_W | PTE_U);
    *((struct UTrapframe *)base) = frame;
    // cprintf("frame va %08x,eip %08x,esp %08x,eflags %08x\n", fault_va,
    // frame.utf_eip, frame.utf_esp, frame.utf_eflags);
    // 调用异常处理函数
    curenv->env_tf.tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
    curenv->env_tf.tf_esp = (uintptr_t)base;
    env_run(curenv);
  } else {
    print_trapframe(tf);
    // Destroy the environment that caused the fault.
    env_destroy(curenv);
  }
}

void trap_handler(struct Trapframe *tf) {
  debug("Got int 3\n");
  while (true) {
    monitor(tf);
  }
}
