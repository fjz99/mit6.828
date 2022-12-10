// implement fork from user space

#include <inc/lib.h>
#include <inc/string.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW 0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
// 我们这里的fork实现是不共享page的，只要有写，就copy一个page，而真正的unix
// fork是只会copy一次，然后就修改另一个进程的页表了
static void pgfault(struct UTrapframe *utf) {
  void *addr = (void *)utf->utf_fault_va;
  uint32_t err = utf->utf_err;
  int r;

  // Check that the faulting access was (1) a write, and (2) to a
  // copy-on-write page.  If not, panic.
  // Hint:
  //   Use the read-only page table mappings at uvpt
  //   (see <inc/memlayout.h>).
  // LAB 4: Your code here.
  pte_t pg = uvpt[(uint32_t)addr >> PGSHIFT];
  if (!((FEC_WR & err) && (pg & PTE_COW)))
    panic("fork's page fault handler err for Env %08x: va %08x eip %08x\n",
          thisenv->env_id, addr, utf->utf_eip);

  // Allocate a new page, map it at a temporary location (PFTEMP),
  // copy the data from the old page to the new page, then move the new
  // page to the old page's address.
  // Hint:
  //   You should make three system calls.
  // 替换map的时候会自动根据引用计数来回收物理page
  // LAB 4: Your code here.
  void *tmp = (void *)PFTEMP;
  // 不能读取全局的thisenv，因为子进程执行时会直接触发pg fault
  envid_t envid = sys_getenvid();
  if ((r = sys_page_alloc(envid, tmp, PTE_W)) < 0)
    panic("sys_page_alloc err: %e", r);
  memcpy(tmp, ROUNDDOWN(addr, PGSIZE), PGSIZE);
  if ((r = sys_page_map(envid, tmp, envid, ROUNDDOWN(addr, PGSIZE), PTE_W)) < 0)
    panic("err sys_page_map");

  if ((r = sys_page_unmap(envid, tmp)) < 0) panic("err sys_page_unmap");
  //   panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)？？暂时没有实现
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
// 把当前地址空间的页号，映射到目的env中，目的env是子进程或当前进程，否则没有访问权限
// 注意支持forktree，所以假如当前的page是COW的，此时也认为是可写的，也需要给子进程设置COW
// 注意先设置子进程为COW+只读，再设置当前进程为COW+只读
// 因为可能正在映射的page刚好是fork函数的代码和数据的位置，所以此时如果先父进程的话,就会直接copy，然后可以W了，子进程映射到了同一个地方，但是只能R，此时出现了不一致
static int duppage(envid_t envid, unsigned pn) {
  int r;
  void *pgaddr = (void *)(pn * PGSIZE);
  int perm = 0;
  pte_t tbl = uvpt[pn];
  if (!(tbl & PTE_P)) return -1;
  if (tbl & PTE_SHARE) {
    // 共享，只复制页表
    if ((r = sys_page_map(thisenv->env_id, pgaddr, envid, pgaddr, tbl & PTE_SYSCALL)) < 0)
      panic("sys_page_map err");
    return 0;
  }
  if ((tbl & PTE_W) || (tbl & PTE_COW)) perm = PTE_COW;
  //   cprintf("duppage:map page [%08x,%08x) with perm %08x\n", pn * PGSIZE,
  //           (pn + 1) * PGSIZE, perm);
  if ((r = sys_page_map(thisenv->env_id, pgaddr, envid, pgaddr, perm)) < 0)
    panic("sys_page_map err");

  // 映射我自己
  if ((r = sys_page_map(thisenv->env_id, pgaddr, thisenv->env_id, pgaddr,
                        perm)) < 0)
    panic("sys_page_map err");

  // LAB 4: Your code here.
  return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t fork(void) {
  // LAB 4: Your code here.
  int r = 0;
  set_pgfault_handler(pgfault);
  envid_t envid = sys_exofork();
  if (envid < 0) return envid;
  if (envid > 0) {
    // if需要有，因为子进程也会执行到这里
    // 分配异常栈page，没必要copy
    if ((r = sys_page_alloc(envid, (void *)UXSTACKTOP - PGSIZE,
                            PTE_U | PTE_P | PTE_W)) < 0)
      panic("err");

    // copy所有的page,本身连页表都没有
    // 防止异常栈被覆盖。。当然后面再设置异常栈也行
    for (size_t i = 0; i < USTACKTOP; i += PGSIZE) {
      pde_t dir = uvpd[PDX(i)];
      //   cprintf("page:[%08x,%08x),dir entry=%08x\n", i, i + PGSIZE, dir);
      if (!(dir & PTE_P)) continue;
      pte_t tbl = uvpt[i / PGSIZE];
      //   cprintf("dir ok page:[%08x,%08x)\n", i, i + PGSIZE);
      if (tbl & PTE_P) duppage(envid, i / PGSIZE);
    }

    // set_pgfault_handler的全局变量已经设置了，所以此时需要手动调用sys call
    // 在fork的时候handler被清空了
    set(envid);

    if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0) panic("err");
  } else {
    // 子进程
    thisenv = &envs[ENVX(sys_getenvid())];
  }
  return envid;

  //   panic("fork not implemented");
}

// Challenge! TODO ...
int sfork(void) {
  panic("sfork not implemented");
  return -E_INVAL;
}
