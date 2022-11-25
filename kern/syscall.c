/* See COPYRIGHT for copyright information. */

#include <inc/assert.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/x86.h>
#include <kern/console.h>
#include <kern/env.h>
#include <kern/pmap.h>
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

  if ((r = envid2env(envid, &e, 1)) < 0) return r;
  if (e == curenv)
    cprintf("[%08x] exiting gracefully\n", curenv->env_id);
  else
    cprintf("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
  env_destroy(e);
  return 0;
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3,
                uint32_t a4, uint32_t a5) {
  // Call the function corresponding to the 'syscallno' parameter.
  // Return any appropriate return value.
  // LAB 3: Your code here.
  debug("SysCall num=%d, args = %08x,%08x,%08x,%08x,%08x\n", syscallno, a1, a2,
        a3, a4, a5);
  switch (syscallno) {
    case SYS_cputs:
      sys_cputs((const char *)a1, (size_t)a2);
      return 0;
    case SYS_cgetc:
      return sys_cgetc();
    case SYS_getenvid:
      return sys_getenvid();
    case SYS_env_destroy:
      sys_env_destroy((envid_t)a1);
      return 0;
    default:
      return -E_INVAL;
  }
}
