// Test preemption by forking off a child process that just spins forever.
// Let it run for a couple time slices, then kill it.

#include <inc/lib.h>

void umain(int argc, char **argv) {
  //   cprintf("I am the child.  Spinning...\n");
  //   while (1) /* do nothing */
  //     ;

  envid_t env;

  cprintf("I am the parent.  Forking the child...\n");
  if ((env = fork()) == 0) {
    cprintf("I am the child.  Spinning...\n");
    while (1) /* do nothing */
      ;
  }

  cprintf("I am the parent.  Running the child...\n");
  sys_yield();
  sys_yield();
  sys_yield();
  sys_yield();
  sys_yield();
  sys_yield();
  sys_yield();
  sys_yield();

  cprintf("I am the parent.  Killing the child...\n");
  sys_env_destroy(env);

  //   if ((env = fork()) == 0) {
  //     cprintf("I am the child.  Spinning...\n");
  // 	return;
  //   }
  //   sys_env_destroy(env);
  //   cprintf("fuck! %08x\n", thisenv->env_id);  //没执行到这里
}
