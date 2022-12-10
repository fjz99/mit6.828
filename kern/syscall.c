/* See COPYRIGHT for copyright information. */

#include <inc/assert.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/x86.h>
#include <kern/console.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/sched.h>
#include <kern/syscall.h>
#include <kern/trap.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void sys_cputs(const char *s, size_t len) {
  // Check that the user has permission to read memory [s, s+len).
  // Destroy the environment if not.

  // LAB 3: Your code here.
  // 传递的参数是用户空间的虚拟地址
  // if (!check_user_mem(curenv->env_pgdir, (void *)s, len, PTE_U)) {
  //   debug("illegal sys_cputs call addr arg %08x\n", s);
  //   env_destroy(curenv);
  // }
  user_mem_assert(curenv, s, len, 0);

  // Print the string supplied by the user.
  cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int sys_cgetc(void) { return cons_getc(); }

// Returns the current environment's envid.
static envid_t sys_getenvid(void) { return curenv->env_id; }

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int sys_env_destroy(envid_t envid) {
  int r;
  struct Env *e;
  // debug("get destory call env %08x\n", envid);
  if ((r = envid2env(envid, &e, 1)) < 0) return r;
  // if (e == curenv)
  //   cprintf("[%08x] exiting gracefully\n", curenv->env_id);
  // else
  //   cprintf("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
  env_destroy(e);
  return 0;
}

// Deschedule current environment and pick a different one to run.
static void sys_yield(void) { sched_yield(); }

static struct Env *get_env(envid_t envid) {
  if (envid < 0) return NULL;
  struct Env *e = &envs[ENVX(envid)];
  if (e->env_status == ENV_FREE || e->env_type != ENV_TYPE_USER) return NULL;
  return e;
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
// copy
// ENV结构，复制寄存器组，但是篡改返回值寄存器EAX，这样，子进程执行的时候就会返回0
// 这个并不是完整的fork，本质上只是fork功能的一部分，在用户态的lib中完成fork
static envid_t sys_exofork(void) {
  // Create the new environment with env_alloc(), from kern/env.c.
  // It should be left as env_alloc created it, except that
  // status is set to ENV_NOT_RUNNABLE, and the register set is copied
  // from the current environment -- but tweaked so sys_exofork
  // will appear to return 0.

  // LAB 4: Your code here.
  struct Env *e;
  int res;
  if ((res = env_alloc(&e, curenv->env_id)) < 0) return res;

  // 不设置虚拟内存，只设置上下文和status
  e->env_status = ENV_NOT_RUNNABLE;
  e->env_tf = curenv->env_tf;
  e->env_tf.tf_regs.reg_eax = 0;  // 设置返回值

  return e->env_id;
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int sys_env_set_status(envid_t envid, int status) {
  // Hint: Use the 'envid2env' function from kern/env.c to translate an
  // envid to a struct Env.
  // You should set envid2env's third argument to 1, which will
  // check whether the current environment has permission to set
  // envid's status.

  // LAB 4: Your code here.
  struct Env *e;
  if (envid2env(envid, &e, true) < 0) return -E_BAD_ENV;
  if (status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE) return -E_INVAL;

  e->env_status = status;
  return 0;
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3), interrupts enabled, and IOPL of 0.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int sys_env_set_trapframe(envid_t envid, struct Trapframe *tf) {
  // LAB 5: Your code here.
  // Remember to check whether the user has supplied us with a good
  // address!
  // panic("sys_env_set_trapframe not implemented");
  struct Env *e;
  if (envid2env(envid, &e, true) < 0) return -E_BAD_ENV;
  user_mem_assert(e, tf, sizeof(struct Trapframe), 0);

  tf->tf_eflags |= FL_IF;
  tf->tf_eflags = (tf->tf_eflags & ~FL_IOPL_MASK) | FL_IOPL_0;  // 保证安全性
  if ((tf->tf_cs & 3) != 3) panic("user invalid tf_cs");
  e->env_tf = *tf;
  return 0;
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int sys_env_set_pgfault_upcall(envid_t envid, void *func) {
  // LAB 4: Your code here.
  // panic("sys_env_set_pgfault_upcall not implemented");

  struct Env *e;
  if (envid2env(envid, &e, true) < 0) return -E_BAD_ENV;
  e->env_pgfault_upcall = func;
  return 0;
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int sys_page_alloc(envid_t envid, void *va, int perm) {
  // Hint: This function is a wrapper around page_alloc() and
  //   page_insert() from kern/pmap.c.
  //   Most of the new code you write should be to check the
  //   parameters for correctness.
  //   If page_insert() fails, remember to free the page you
  //   allocated!

  // LAB 4: Your code here.
  struct Env *e;
  if (envid2env(envid, &e, true) < 0) return -E_BAD_ENV;
  if ((uint32_t)va % PGSIZE || va >= (void *)UTOP) return -E_INVAL;
  if (perm & ~PTE_SYSCALL) return -E_INVAL;
  struct PageInfo *pg = page_alloc(ALLOC_ZERO);
  if (!pg) return -E_NO_MEM;

  // insert内自动unmap了已经map的page
  if (page_insert(e->env_pgdir, pg, va, perm | PTE_U | PTE_P)) {
    page_free(pg);
    return -E_NO_MEM;
  }
  return 0;
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
// 注意是把dst的pgdir映射到和src一致
static int sys_page_map(envid_t srcenvid, void *srcva, envid_t dstenvid,
                        void *dstva, int perm) {
  // Hint: This function is a wrapper around page_lookup() and
  //   page_insert() from kern/pmap.c.
  //   Again, most of the new code you write should be to check the
  //   parameters for correctness.
  //   Use the third argument to page_lookup() to
  //   check the current permissions on the page.

  // LAB 4: Your code here.
  struct Env *src, *dst;
  if (envid2env(srcenvid, &src, true) < 0 ||
      envid2env(dstenvid, &dst, true) < 0)
    return -E_BAD_ENV;
  if ((uint32_t)srcva % PGSIZE || srcva >= (void *)UTOP) return -E_INVAL;
  if ((uint32_t)dstva % PGSIZE || dstva >= (void *)UTOP) return -E_INVAL;

  pte_t *pte;
  struct PageInfo *pg = page_lookup(src->env_pgdir, srcva, &pte);
  if (!pg) return -E_INVAL;
  if (!(*pte & PTE_W) && (perm & PTE_W)) return -E_INVAL;
  if (perm & ~PTE_SYSCALL) return -E_INVAL;

  if (page_insert(dst->env_pgdir, pg, dstva, perm | PTE_P | PTE_U)) {
    page_free(pg);
    return -E_NO_MEM;
  }
  return 0;
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int sys_page_unmap(envid_t envid, void *va) {
  // Hint: This function is a wrapper around page_remove().

  // LAB 4: Your code here.
  struct Env *e;
  if (envid2env(envid, &e, true) < 0) return -E_BAD_ENV;
  if ((uint32_t)va % PGSIZE || va >= (void *)UTOP) return -E_INVAL;
  page_remove(e->env_pgdir, va);
  return 0;
  // panic("sys_page_unmap not implemented");
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva,
                            unsigned perm) {
  // LAB 4: Your code here.

  int r;
  struct Env *e;
  // debug("send to %08x,srcva %08x,perm %08x\n", envid, srcva, perm);
  if ((r = envid2env(envid, &e, false)) < 0) return r;
  if (!e->env_ipc_recving) return -E_IPC_NOT_RECV;
  if (srcva < (void *)UTOP) {
    // 需要发送一个page
    if ((uint32_t)srcva % PGSIZE) {
      // panic("PGSIZE \n");
      return -E_INVAL;
    }
    if (perm & ~PTE_SYSCALL) {
      // panic("perm \n");
      return -E_INVAL;
    }
    pte_t *tbl = NULL;
    struct PageInfo *pg = NULL;
    if ((pg = page_lookup(curenv->env_pgdir, srcva, &tbl)) == NULL) {
      // panic("look up\n");
      return -E_INVAL;
    }
    if ((perm & PTE_W) && !(*tbl & PTE_W)) {
      // cprintf("%08x\n", page2pa(pg));
      // panic("%08x\n", *tbl);
      return -E_INVAL;
    }

    if (e->env_ipc_dstva) {
      // 只有要接收才会map一下
      // 手动map，因为sys_page_map中的checkperm为true
      if ((r = page_insert(e->env_pgdir, pg, e->env_ipc_dstva,
                           perm | PTE_P | PTE_U)) < 0) {
        page_free(pg);
        return r;
      }
    }
    e->env_ipc_perm = perm;
  } else {
    e->env_ipc_perm = 0;
  }
  assert(e->env_status == ENV_NOT_RUNNABLE);
  e->env_ipc_recving = false;  // 清空标志位
  e->env_ipc_dstva = NULL;
  e->env_ipc_value = value;  // 发送value
  e->env_status = ENV_RUNNABLE;
  e->env_ipc_from = curenv->env_id;
  return 0;
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int sys_ipc_recv(void *dstva) {
  // LAB 4: Your code here.
  // panic("sys_ipc_recv not implemented");
  // debug("Env %08x start recv\n", curenv->env_id);
  if (dstva < (void *)UTOP) {
    if ((uint32_t)dstva % PGSIZE) return -E_INVAL;
    curenv->env_ipc_dstva = dstva;
  } else
    curenv->env_ipc_dstva = NULL;
  curenv->env_ipc_recving = true;
  curenv->env_status = ENV_NOT_RUNNABLE;
  return 0;  // 返回后，在syscall处会重新调度的，而且这样可以设置syscall的返回值
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3,
                uint32_t a4, uint32_t a5) {
  // Call the function corresponding to the 'syscallno' parameter.
  // Return any appropriate return value.
  // LAB 3: Your code here.
  // debug("SysCall num=%d, args = %08x,%08x,%08x,%08x,%08x\n", syscallno, a1,
  // a2,
  //       a3, a4, a5);
  switch (syscallno) {
    case SYS_cputs:
      sys_cputs((const char *)a1, (size_t)a2);
      return 0;
    case SYS_cgetc:
      return sys_cgetc();
    case SYS_getenvid:
      return sys_getenvid();
    case SYS_env_destroy:
      return sys_env_destroy((envid_t)a1);
    case SYS_yield:
      sys_yield();
      return 0;
    case SYS_page_alloc:
      return sys_page_alloc(a1, (void *)a2, a3);
    case SYS_page_map:
      return sys_page_map(a1, (void *)a2, a3, (void *)a4, a5);
    case SYS_page_unmap:
      return sys_page_unmap(a1, (void *)a2);
    case SYS_exofork:
      return sys_exofork();
    case SYS_env_set_status:
      return sys_env_set_status(a1, a2);
    case SYS_ipc_try_send:
      return sys_ipc_try_send(a1, a2, (void *)a3, a4);
    case SYS_ipc_recv:
      return sys_ipc_recv((void *)a1);
    case SYS_env_set_pgfault_upcall:
      return sys_env_set_pgfault_upcall(a1, (void *)a2);
    case SYS_env_set_trapframe:
      return sys_env_set_trapframe(a1, (struct Trapframe *)a2);
    default:
      return -E_INVAL;
  }
}
