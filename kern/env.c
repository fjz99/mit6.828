/* See COPYRIGHT for copyright information. */

#include <inc/assert.h>
#include <inc/elf.h>
#include <inc/error.h>
#include <inc/mmu.h>
#include <inc/string.h>
#include <inc/x86.h>
#include <kern/env.h>
#include <kern/kdebug.h>
#include <kern/monitor.h>
#include <kern/pmap.h>
#include <kern/sched.h>
#include <kern/spinlock.h>
#include <kern/trap.h>

struct Env *envs = NULL;           // All environments
static struct Env *env_free_list;  // Free environment list
                                   // (linked by Env->env_link)

#define ENVGENSHIFT 12  // >= LOGNENV

// Global descriptor table.
//
// Set up global descriptor table (GDT) with separate segments for
// kernel mode and user mode.  Segments serve many purposes on the x86.
// We don't use any of their memory-mapping capabilities, but we need
// them to switch privilege levels.
//
// The kernel and user segments are identical except for the DPL.
// To load the SS register, the CPL must equal the DPL.  Thus,
// we must duplicate the segments for the user and the kernel.
//
// In particular, the last argument to the SEG macro used in the
// definition of gdt specifies the Descriptor Privilege Level (DPL)
// of that descriptor: 0 for kernel and 3 for user.
//
// 其实段的大小都是最大，只是多了权限位而已
struct Segdesc gdt[] = {
    // 0x0 - unused (always faults -- for trapping NULL far pointers)
    SEG_NULL,

    // 0x8 - kernel code segment
    [GD_KT >> 3] = SEG(STA_X | STA_R, 0x0, 0xffffffff, 0),

    // 0x10 - kernel data segment
    [GD_KD >> 3] = SEG(STA_W, 0x0, 0xffffffff, 0),

    // 0x18 - user code segment
    [GD_UT >> 3] = SEG(STA_X | STA_R, 0x0, 0xffffffff, 3),

    // 0x20 - user data segment
    [GD_UD >> 3] = SEG(STA_W, 0x0, 0xffffffff, 3),

    // 0x28 - tss, initialized in trap_init_percpu()
    [GD_TSS0 >> 3] = SEG_NULL,

    // 需要初始化一下，N个CPU的选择符。。
    [0x30] = SEG_NULL, [0x38] = SEG_NULL,
    [0x40] = SEG_NULL,  //凑一下答案，到4个cpu就行了
};

struct Pseudodesc gdt_pd = {sizeof(gdt) - 1, (unsigned long)gdt};

//
// Converts an envid to an env pointer.
// If checkperm is set, the specified environment must be either the
// current environment or an immediate child of the current environment.
//
// RETURNS
//   0 on success, -E_BAD_ENV on error.
//   On success, sets *env_store to the environment.
//   On error, sets *env_store to NULL.
//
int envid2env(envid_t envid, struct Env **env_store, bool checkperm) {
  struct Env *e;

  // If envid is zero, return the current environment.
  if (envid == 0) {
    *env_store = curenv;
    return 0;
  }

  // Look up the Env structure via the index part of the envid,
  // then check the env_id field in that struct Env
  // to ensure that the envid is not stale
  // (i.e., does not refer to a _previous_ environment
  // that used the same slot in the envs[] array).
  e = &envs[ENVX(envid)];
  if (e->env_status == ENV_FREE || e->env_id != envid) {
    *env_store = 0;
    return -E_BAD_ENV;
  }

  // Check that the calling environment has legitimate permission
  // to manipulate the specified environment.
  // If checkperm is set, the specified environment
  // must be either the current environment
  // or an immediate child of the current environment.
  if (checkperm && e != curenv && e->env_parent_id != curenv->env_id) {
    *env_store = 0;
    return -E_BAD_ENV;
  }

  *env_store = e;
  return 0;
}

// Mark all environments in 'envs' as free, set their env_ids to 0,
// and insert them into the env_free_list.
// Make sure the environments are in the free list in the same order
// they are in the envs array (i.e., so that the first call to
// env_alloc() returns envs[0]).
//
void env_init(void) {
  // Set up envs array
  // LAB 3: Your code here.
  env_free_list = envs;
  for (int i = 1; i < NENV; ++i) {
    envs[i - 1].env_link = &envs[i];
  }
  // Per-CPU part of the initialization
  env_init_percpu();
}

// Load GDT and segment descriptors.
void env_init_percpu(void) {
  lgdt(&gdt_pd);

  // 加载当前的段描述符
  // The kernel never uses GS or FS, so we leave those set to
  // the user data segment.
  asm volatile("movw %%ax,%%gs" : : "a"(GD_UD | 3));
  asm volatile("movw %%ax,%%fs" : : "a"(GD_UD | 3));
  // The kernel does use ES, DS, and SS.  We'll change between
  // the kernel and user data segments as needed.
  asm volatile("movw %%ax,%%es" : : "a"(GD_KD));
  asm volatile("movw %%ax,%%ds" : : "a"(GD_KD));
  asm volatile("movw %%ax,%%ss" : : "a"(GD_KD));
  // Load the kernel text segment into CS.
  // 即只有jmp指令才能设置代码段
  asm volatile("ljmp %0,$1f\n 1:\n" : : "i"(GD_KT));
  // For good measure, clear the local descriptor table (LDT),
  // since we don't use it.
  lldt(0);
}

//
// Initialize the kernel virtual memory layout for environment e.
// Allocate a page directory, set e->env_pgdir accordingly,
// and initialize the kernel portion of the new environment's address space.
// Do NOT (yet) map anything into the user portion
// of the environment's virtual address space.
//
// Returns 0 on success, < 0 on error.  Errors include:
//	-E_NO_MEM if page directory or table could not be allocated.
//
// 只映射内核空间
static int env_setup_vm(struct Env *e) {
  int i;
  struct PageInfo *p = NULL;

  // Allocate a page for the page directory
  if (!(p = page_alloc(ALLOC_ZERO))) return -E_NO_MEM;

  // Now, set e->env_pgdir and initialize the page directory.
  //
  // Hint:
  //    - The VA space of all envs is identical above UTOP
  //	(except at UVPT, which we've set below).
  //	See inc/memlayout.h for permissions and layout.
  //	Can you use kern_pgdir as a template?  Hint: Yes.
  //	(Make sure you got the permissions right in Lab 2.)
  //    - The initial VA below UTOP is empty.
  //    - You do not need to make any more calls to page_alloc.
  //    - Note: In general, pp_ref is not maintained for
  //	physical pages mapped only above UTOP, but env_pgdir
  //	is an exception -- you need to increment env_pgdir's
  //	pp_ref for env_free to work correctly.
  //    - The functions in kern/pmap.h are handy.

  // LAB 3: Your code here.
  // 初始化页表，用户空间无所谓，主要是复用内核空间的pg tbl
  // 而且内核的页表已经完全映射过了，所以不用担心再次修改内核页表要级联修改其他进程的页表的问题
  // 映射UTOP之上的，除了page dir之外的部分
  p->pp_ref++;
  e->env_pgdir = page2kva(
      p);  //这里是虚拟地址，因为fork是系统调用，在内核态执行，而且虚拟地址才能被C语言访问
  for (size_t i = PDX(UTOP); i < PDX(UVPT); ++i) {
    //不能直接复制页表。。
    e->env_pgdir[i] = kern_pgdir[i];
    //需要++引用，否则当user的pgdir释放的时候，会导致内核的页表被释放
    pa2page(PTE_ADDR(kern_pgdir[i]))->pp_ref++;
  }
  for (size_t i = PDX(ULIM); i <= PDX(~0); ++i) {
    e->env_pgdir[i] = kern_pgdir[i];
    pa2page(PTE_ADDR(kern_pgdir[i]))->pp_ref++;
  }

  // UVPT maps the env's own page table read-only.
  // Permissions: kernel R, user R
  // 这里增加了一个自我映射，结果就是把两级页表变成一级了
  // 因为1,2级页表都是1024项，那么假如本来访问的是0,1,12
  // 现在会根据1找到pg dir的1号，即二级页表，然后找二级页表中为12号的页表项
  // 所以我们就可以从UVPT开始访问页表的内容了，总共1024*1024个page，注意提前判断有没有page
  e->env_pgdir[PDX(UVPT)] = PADDR(e->env_pgdir) | PTE_P | PTE_U;

  return 0;
}

//
// Allocates and initializes a new environment.
// On success, the new environment is stored in *newenv_store.
//
// Returns 0 on success, < 0 on failure.  Errors include:
//	-E_NO_FREE_ENV if all NENV environments are allocated
//	-E_NO_MEM on memory exhaustion
//
int env_alloc(struct Env **newenv_store, envid_t parent_id) {
  int32_t generation;
  int r;
  struct Env *e;

  if (!(e = env_free_list)) return -E_NO_FREE_ENV;

  // Allocate and set up the page directory for this environment.
  if ((r = env_setup_vm(e)) < 0) return r;

  // Generate an env_id for this environment.
  generation = (e->env_id + (1 << ENVGENSHIFT)) & ~(NENV - 1);
  if (generation <= 0)  // Don't create a negative env_id.
    generation = 1 << ENVGENSHIFT;
  e->env_id = generation | (e - envs);

  // Set the basic status variables.
  e->env_parent_id = parent_id;
  e->env_type = ENV_TYPE_USER;
  e->env_status = ENV_RUNNABLE;
  e->env_runs = 0;

  // Clear out all the saved register state,
  // to prevent the register values
  // of a prior environment inhabiting this Env structure
  // from "leaking" into our new environment.
  memset(&e->env_tf, 0, sizeof(e->env_tf));

  // Set up appropriate initial values for the segment registers.
  // GD_UD is the user data segment selector in the GDT, and
  // GD_UT is the user text segment selector (see inc/memlayout.h).
  // The low 2 bits of each segment register contains the
  // Requestor Privilege Level (RPL); 3 means user mode.  When
  // we switch privilege levels, the hardware does various
  // checks involving the RPL and the Descriptor Privilege Level
  // (DPL) stored in the descriptors themselves.
  e->env_tf.tf_ds = GD_UD | 3;
  e->env_tf.tf_es = GD_UD | 3;
  e->env_tf.tf_ss = GD_UD | 3;
  e->env_tf.tf_esp = USTACKTOP;
  e->env_tf.tf_cs = GD_UT | 3;
  // You will set e->env_tf.tf_eip later.

  // Enable interrupts while in user mode.
  // LAB 4: Your code here.
  // 修改eflags即可,这也的话，每次env run都会启动中断
  e->env_tf.tf_eflags |= FL_IF;

  // Clear the page fault handler until user installs one.
  e->env_pgfault_upcall = 0;

  // Also clear the IPC receiving flag.
  e->env_ipc_recving = 0;

  // commit the allocation
  env_free_list = e->env_link;
  *newenv_store = e;

  cprintf("[%08x] new env %08x\n", curenv ? curenv->env_id : 0, e->env_id);
  return 0;
}

//
// Allocate len bytes of physical memory for environment env,
// and map it at virtual address va in the environment's address space.
// Does not zero or otherwise initialize the mapped pages in any way.
// Pages should be writable by user and kernel.
// Panic if any allocation attempt fails.
//
// va会向下取整，len会向上取整
static void region_alloc(struct Env *e, void *va, size_t len) {
  // LAB 3: Your code here.
  // (But only if you need it for load_icode.)
  //
  // Hint: It is easier to use region_alloc if the caller can pass
  //   'va' and 'len' values that are not page-aligned.
  //   You should round va down, and round (va + len) up.
  //   (Watch out for corner-cases!)
  // debug("mapping %08x,size=%08x\n", va, len);
  va = ROUNDDOWN(va, PGSIZE);
  void *end = ROUNDUP(va + len, PGSIZE);
  if (va >= (void *)UTOP) panic("va > UTOP!");
  void *p = va;
  while (p < end) {
    // debug("mapping %08x\n", p);
    pte_t *pg = pgdir_walk(e->env_pgdir, p, true);
    if (!pg) panic("page tbl alloc err");
    //这个addr已经映射了,其实是有可能的，因为前面有向上取整，向页对齐的操作，映射了就不分配物理页了
    if (!*pg) {
      struct PageInfo *info = page_alloc(0);
      if (!info) panic("OOM err");
      info->pp_ref++;
      *pg = page2pa(info) | PTE_P | PTE_W | PTE_U;
    }

    // if (*pg) {
    //   _backtrace();
    //   panic("va %08x refer to an used mem mapping %08x", p, *pg);
    // }

    p += PGSIZE;
  }
}

//
// Set up the initial program binary, stack, and processor flags
// for a user process.
// This function is ONLY called during kernel initialization,
// before running the first user-mode environment.
//
// This function loads all loadable segments from the ELF binary image
// into the environment's user memory, starting at the appropriate
// virtual addresses indicated in the ELF program header.
// At the same time it clears to zero any portions of these segments
// that are marked in the program header as being mapped
// but not actually present in the ELF file - i.e., the program's bss section.
//
// All this is very similar to what our boot loader does, except the boot
// loader also needs to read the code from disk.  Take a look at
// boot/main.c to get ideas.
//
// Finally, this function maps one page for the program's initial stack.
//
// load_icode panics if it encounters problems.
//  - How might load_icode fail?  What might be wrong with the given input?
//
// 加载ELF，并映射用户空间
static void load_icode(struct Env *e, uint8_t *binary) {
  // Hints:
  //  Load each program segment into virtual memory
  //  at the address specified in the ELF segment header.
  //  You should only load segments with ph->p_type == ELF_PROG_LOAD.
  //  Each segment's virtual address can be found in ph->p_va
  //  and its size in memory can be found in ph->p_memsz.
  //  The ph->p_filesz bytes from the ELF binary, starting at
  //  'binary + ph->p_offset', should be copied to virtual address
  //  ph->p_va.  Any remaining memory bytes should be cleared to zero.
  //  (The ELF header should have ph->p_filesz <= ph->p_memsz.)
  //  Use functions from the previous lab to allocate and map pages.
  //
  //  All page protection bits should be user read/write for now.
  //  ELF segments are not necessarily page-aligned, but you can
  //  assume for this function that no two segments will touch
  //  the same virtual page.
  //
  //  You may find a function like region_alloc useful.
  //
  //  Loading the segments is much simpler if you can move data
  //  directly into the virtual addresses stored in the ELF binary.
  //  So which page directory should be in force during
  //  this function?
  //
  //  You must also do something with the program's entry point,
  //  to make sure that the environment starts executing there.
  //  What?  (See env_run() and env_pop_tf() below.)

  // LAB 3: Your code here.
  struct Elf *elf = (struct Elf *)binary;
  if (elf->e_magic != ELF_MAGIC) panic("elf magic err");

  struct Proghdr *ph, *eph;
  ph = (struct Proghdr *)((uint8_t *)elf + elf->e_phoff);
  eph = ph + elf->e_phnum;
  for (; ph < eph; ph++) {
    //加载每个段
    if (ph->p_type == ELF_PROG_LOAD) {
      // debug("load elf: to va [%08x-%08x] , memsize %08x,file size %08x\n",
      // ph->p_va, ph->p_va + ph->p_memsz, ph->p_memsz, ph->p_filesz);
      // 注意分配的时候按照大的分配，否则ph->p_memsz > ph->p_filesz的时候会错误
      region_alloc(e, (void *)ph->p_va, ph->p_memsz);

      //下面将内核地址空间中的elf加载到用户地址空间的虚拟地址中
      //注意此时还没有加载用户进程的页表，所以现在只能暂时使用物理地址进行转换
      //注意未必是连续的物理page，所以要一直转换！
      physaddr_t pa = map_va2pa(e->env_pgdir, (void *)ph->p_va);
      uint8_t *kva = (uint8_t *)KADDR(pa), *uva = (uint8_t *)ph->p_va,
              *input_start = (uint8_t *)(binary + ph->p_offset);
      for (int i = 0; i < ph->p_memsz; ++i) {
        if (!((uint32_t)uva % PGSIZE)) {
          //刚好到达页边界
          pa = map_va2pa(e->env_pgdir, uva);
          kva = (uint8_t *)KADDR(pa);
        }

        if (i < ph->p_filesz) {
          *kva = *input_start;
        } else {
          *kva = 0;
        }
        uva++;
        kva++;
        input_start++;
      }
    }
  }

  // 别忘了设置程序入口,cs在alloc中设置了
  e->env_tf.tf_eip = (uintptr_t)elf->e_entry;

  // Now map one page for the program's initial stack
  // at virtual address USTACKTOP - PGSIZE.

  // LAB 3: Your code here.
  region_alloc(e, (void *)(USTACKTOP - PGSIZE), PGSIZE);
}

//
// Allocates a new env with env_alloc, loads the named elf
// binary into it with load_icode, and sets its env_type.
// This function is ONLY called during kernel initialization,
// before running the first user-mode environment.
// The new env's parent ID is set to 0.
//
void env_create(uint8_t *binary, enum EnvType type) {
  // LAB 3: Your code here.
  struct Env *e;
  int rt = 0;
  if ((rt = env_alloc(&e, 0)) < 0) {
    panic("env alloc err %e", rt);
  }

  load_icode(e, binary);
  e->env_type = type;
}

//
// Frees env e and all memory it uses.
//
void env_free(struct Env *e) {
  pte_t *pt;
  uint32_t pdeno, pteno;
  physaddr_t pa;

  // If freeing the current environment, switch to kern_pgdir
  // before freeing the page directory, just in case the page
  // gets reused.
  if (e == curenv) lcr3(PADDR(kern_pgdir));

  // Note the environment's demise.
  cprintf("[%08x] free env %08x\n", curenv ? curenv->env_id : 0, e->env_id);

  // Flush all mapped pages in the user portion of the address space
  // 通过遍历两级页表来free分配的内存映射
  static_assert(UTOP % PTSIZE == 0);
  for (pdeno = 0; pdeno < PDX(UTOP); pdeno++) {
    // only look at mapped page tables
    if (!(e->env_pgdir[pdeno] & PTE_P)) continue;

    // find the pa and va of the page table
    pa = PTE_ADDR(e->env_pgdir[pdeno]);
    pt = (pte_t *)KADDR(pa);

    // unmap all PTEs in this page table
    for (pteno = 0; pteno <= PTX(~0); pteno++) {
      if (pt[pteno] & PTE_P) page_remove(e->env_pgdir, PGADDR(pdeno, pteno, 0));
    }

    // free the page table itself
    e->env_pgdir[pdeno] = 0;
    page_decref(pa2page(pa));
  }

  // free the page directory
  pa = PADDR(e->env_pgdir);
  e->env_pgdir = 0;
  page_decref(pa2page(pa));

  // return the environment to the free list
  e->env_status = ENV_FREE;
  e->env_link = env_free_list;
  env_free_list = e;
}

//
// Frees environment e.
//
void env_destroy(struct Env *e) {
  if (e == curenv) curenv == NULL;
  env_free(e);

  //我改的，多任务的情况下，进程终止后再次进行一次调度
  //在外部调度，保证成功设置syscall的返回值
  // sched_yield();
  // cprintf("Destroyed the only environment - nothing more to do!\n");
  // while (1) monitor(NULL);
}

//
// Restores the register values in the Trapframe with the 'iret' instruction.
// This exits the kernel and starts executing some environment's code.
//
// This function does not return.
//
// 恢复上下文，在汇编中return了
void env_pop_tf(struct Trapframe *tf) {
  asm volatile(
      "\tmovl %0,%%esp\n"
      "\tpopal\n"
      "\tpopl %%es\n"
      "\tpopl %%ds\n"
      "\taddl $0x8,%%esp\n" /* skip tf_trapno and tf_errcode */
      "\tiret\n"
      :
      : "g"(tf)
      : "memory");
  panic("iret failed"); /* mostly to placate the compiler */
}

//
// Context switch from curenv to env e.
// Note: if this is the first call to env_run, curenv is NULL.
//
// This function does not return.
//
// 实现进程上下文切换
void env_run(struct Env *e) {
  // Step 1: If this is a context switch (a new environment is running):
  //	   1. Set the current environment (if any) back to
  //	      ENV_RUNNABLE if it is ENV_RUNNING (think about
  //	      what other states it can be in),
  //	   2. Set 'curenv' to the new environment,
  //	   3. Set its status to ENV_RUNNING,
  //	   4. Update its 'env_runs' counter,
  //	   5. Use lcr3() to switch to its address space.
  // Step 2: Use env_pop_tf() to restore the environment's
  //	   registers and drop into user mode in the
  //	   environment.

  // Hint: This function loads the new environment's state from
  //	e->env_tf.  Go back through the code you wrote above
  //	and make sure you have set the relevant parts of
  //	e->env_tf to sensible values.

  // LAB 3: Your code here.
  // _backtrace();
  // debug("CPU %d run env %08x :eip %08x\n", thiscpu->cpu_id, e->env_id,
  // e->env_tf.tf_eip);
  // assert(e->env_tf.tf_eflags & FL_IF);
  if (curenv != NULL) {
    //其他情况可能是block等，就不能为runnable
    if (curenv->env_status == ENV_RUNNING) curenv->env_status = ENV_RUNNABLE;
  }
  curenv = e;
  e->env_status = ENV_RUNNING;
  e->env_runs++;
  e->env_cpunum = cpunum();//！！

  //自我运行的时候会重新切换一次页表。。
  lcr3(PADDR(e->env_pgdir));  //物理地址。。

  unlock_kernel();
  env_pop_tf(&e->env_tf);
}
