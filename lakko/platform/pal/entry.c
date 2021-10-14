#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <asm/prctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <err.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>

#include "lakko.h"
#include "mmu.h"
#include "cpu-x86.h"
#include "local.h"
#include "debug.h"

#define BUILD_ASSERT(cond) do { (void) sizeof(char [1 - 2*!(cond)]); } while(0)

ptent_t *pgroot;
uintptr_t phys_limit;
uintptr_t mmap_base;
uintptr_t stack_base;

int walnut_fd;

static struct idtd idt[IDT_ENTRIES];

static uint64_t gdt_template[NR_GDT_ENTRIES] = {
	0,
	0,
	SEG64(SEG_X | SEG_R, 0),
	SEG64(SEG_W, 0),
	0,
	SEG64(SEG_W, 3),
	SEG64(SEG_X | SEG_R, 3),
	0,
	0,
};

struct lakko_percpu {
	uint64_t percpu_ptr;
	uint64_t tmp;
	uint64_t kfs_base;
	uint64_t ufs_base;
	uint64_t in_usermode;
	struct Tss tss;
	uint64_t gdt[NR_GDT_ENTRIES];
} __attribute__((packed));

static __thread struct lakko_percpu *lpercpu;

struct dynsym {
	char		*ds_name;
	int		ds_idx;
	int		ds_off;
	struct dynsym	*ds_next;
};

unsigned long lakko_get_user_fs(void)
{
	void *ptr;
	asm("movq %%gs:%c[ufs_base], %0" : "=r"(ptr) :
	    [ufs_base]"i"(offsetof(struct lakko_percpu, ufs_base)) : "memory");
	return (unsigned long) ptr;
}

void lakko_set_user_fs(unsigned long fs_base)
{
	asm ("movq %0, %%gs:%c[ufs_base]" : : "r"(fs_base),
	     [ufs_base]"i"(offsetof(struct lakko_percpu, ufs_base)));
}

static void map_ptr(void *p, int len)
{
	unsigned long page = PGADDR(p);
	unsigned long page_end = PGADDR((char*) p + len);
	unsigned long l = (page_end - page) + PGSIZE;
	void *pg = (void*) page;

	lakko_vm_map_phys(pgroot, pg, l, (void*) lakko_va_to_pa(pg),
			 PERM_R | PERM_W);
}

#define SAFE_STACK_SIZE (2048 * 1024)
#define SAFE_STACKS 2 /* Must be less than 8 */

static int setup_safe_stack(struct lakko_percpu *percpu)
{
	int i;
	char *safe_stack[SAFE_STACKS];

	for (i = 0; i < SAFE_STACKS; i++) {
		safe_stack[i] = mmap(NULL, SAFE_STACK_SIZE, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (safe_stack[i] == MAP_FAILED) {
			printf("map failed i = %d\n", i);
			return -ENOMEM;
		}

		map_ptr(safe_stack[i], SAFE_STACK_SIZE);

		safe_stack[i] += SAFE_STACK_SIZE;
	}

	percpu->tss.tss_iomb = offsetof(struct Tss, tss_iopb);

	/* Note: tss_ist[0] is ignored */
	for (i = 0; i < SAFE_STACKS; i++)
		percpu->tss.tss_ist[i + 1] = (uintptr_t) safe_stack[i];

	/* changed later on jump to G3 */
	percpu->tss.tss_rsp[0] = (uintptr_t) safe_stack[0];

	return 0;
}

static void setup_gdt(struct lakko_percpu *percpu)
{	
	memcpy(percpu->gdt, gdt_template, sizeof(uint64_t) * NR_GDT_ENTRIES);

	percpu->gdt[GD_TSS >> 3] = (SEG_TSSA | SEG_P | SEG_A |
				    SEG_BASELO(&percpu->tss) |
				    SEG_LIM(sizeof(struct Tss) - 1));
	percpu->gdt[GD_TSS2 >> 3] = SEG_BASEHI(&percpu->tss);
}

/**
 * lakko_boot - Brings the user-level OS online
 * @percpu: the thread-local data
 */
static int lakko_boot(struct lakko_percpu *percpu)
{
	struct tptr _idtr, _gdtr;

	setup_gdt(percpu);

	_gdtr.base  = (uint64_t) &percpu->gdt;
	_gdtr.limit = sizeof(percpu->gdt) - 1;

	_idtr.base = (uint64_t) &idt;
	_idtr.limit = sizeof(idt) - 1;

	asm volatile (
		// STEP 1: load the new GDT
		"lgdt %0\n"

		// STEP 2: initialize data segements
		"mov $" __str(GD_KD) ", %%ax\n"
		"mov %%ax, %%ds\n"
		"mov %%ax, %%es\n"
		"mov %%ax, %%ss\n"

		// STEP 3: long jump into the new code segment
		"mov $" __str(GD_KT) ", %%rax\n"
		"pushq %%rax\n"
		"pushq $1f\n"
		"lretq\n"
		"1:\n"
		"nop\n"

		// STEP 4: load the task register (for safe stack switching)
		"mov $" __str(GD_TSS) ", %%ax\n"
		"ltr %%ax\n"

		// STEP 5: load the new IDT and enable interrupts
		"lidt %1\n"
		"sti\n"

		: : "m" (_gdtr), "m" (_idtr) : "rax");
	
	// STEP 6: FS and GS require special initialization on 64-bit
	wrmsrl(MSR_FS_BASE, percpu->kfs_base);
	wrmsrl(MSR_GS_BASE, (unsigned long) percpu);

	return 0;
}

#define ISR_LEN 16

static inline void set_idt_addr(struct idtd *id, physaddr_t addr)
{       
        id->low    = addr & 0xFFFF;
        id->middle = (addr >> 16) & 0xFFFF;
        id->high   = (addr >> 32) & 0xFFFFFFFF;
}

static void setup_idt(void)
{
	int i;

	for (i = 0; i < IDT_ENTRIES; i++) {
		struct idtd *id = &idt[i];
		uintptr_t isr = (uintptr_t) &__lakko_intr;

		isr += ISR_LEN * i;
		memset(id, 0, sizeof(*id));
                
		id->selector = GD_KT;
		/* We must use interrupts gates otherwise nested interrupts will
		 * corrupt the alternative stack. */
		id->type     = IDTD_P | IDTD_INTERRUPT_GATE;
		id->ist	     = 1;

		switch (i) {
		case T_PGFLT:
			/* We muse use another alternative stack otherwise a
			 * page fault that occurs during interrupt processing
			 * will corrupt the stack. */
			id->ist = 2;
			break;
		case T_BRKPT:
			id->type |= IDTD_CPL3;
			break;
		}

		set_idt_addr(id, isr);
	}
}

static int setup_syscall(void)
{
	unsigned long lstar;
	unsigned long lstara;
	unsigned char *page;
	ptent_t *pte;
	size_t off;
	int i;

	assert((unsigned long) __lakko_syscall_end  -
	       (unsigned long) __lakko_syscall < PGSIZE);

	lstar = ioctl(walnut_fd, WALNUT_GET_SYSCALL);
	if (lstar == -1)
		return -errno;

	page = mmap((void *) NULL, PGSIZE * 2,
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANON, -1, 0);

	if (page == MAP_FAILED)
		return -errno;

	lstara = lstar & ~(PGSIZE - 1);
	off = lstar - lstara;

	memcpy(page + off, __lakko_syscall, 
		(unsigned long) __lakko_syscall_end -
		(unsigned long) __lakko_syscall);

	for (i = 0; i <= PGSIZE; i += PGSIZE) {
		uintptr_t pa = lakko_mmap_addr_to_pa(page + i);
		lakko_vm_lookup(pgroot, (void *) (lstara + i), 1, &pte);
		*pte = PTE_ADDR(pa) | PTE_P;
	}
	
	return 0;
}

#define VSYSCALL_ADDR 0xffffffffff600000

static void setup_vsyscall(void)
{
	ptent_t *pte;

	lakko_vm_lookup(pgroot, (void *) VSYSCALL_ADDR, 1, &pte);
	*pte = PTE_ADDR(lakko_va_to_pa(&__lakko_vsyscall_page)) | PTE_P | PTE_U;
}

static void __setup_mappings_cb(const struct lakko_procmap_entry *ent)
{
	int perm = PERM_NONE;
	int ret;

	// page region already mapped
	if (ent->begin == (unsigned long) PAGEBASE)
		return;
	
	if (ent->begin == (unsigned long) VSYSCALL_ADDR) {
		setup_vsyscall();
		return;
	}

	if (ent->type == PROCMAP_TYPE_VDSO) {
		lakko_vm_map_phys(pgroot, (void *) ent->begin, ent->end - ent->begin, (void *) lakko_va_to_pa((void *) ent->begin), PERM_U | PERM_R | PERM_X);
		return;
	}

	if (ent->type == PROCMAP_TYPE_VVAR) {
		lakko_vm_map_phys(pgroot, (void *) ent->begin, ent->end - ent->begin, (void *) lakko_va_to_pa((void *) ent->begin), PERM_U | PERM_R);
		return;
	}

	if (ent->r)
		perm |= PERM_R;
	if (ent->w)
		perm |= PERM_W;
	if (ent->x)
		perm |= PERM_X;

	ret = lakko_vm_map_phys(pgroot, (void *) ent->begin,
			      ent->end - ent->begin,
			      (void *) lakko_va_to_pa((void *) ent->begin),
			      perm);
	assert(!ret);
}

static int __setup_mappings_precise(void)
{
	int ret;

	ret = lakko_vm_map_phys(pgroot, (void *) PAGEBASE,
			      MAX_PAGES * PGSIZE,
			      (void *) lakko_va_to_pa((void *) PAGEBASE),
			      PERM_R | PERM_W | PERM_BIG);
	if (ret)
		return ret;

	lakko_procmap_iterate(&__setup_mappings_cb);

	return 0;
}

static void setup_vdso_cb(const struct lakko_procmap_entry *ent)
{
	if (ent->type == PROCMAP_TYPE_VDSO) {
		lakko_vm_map_phys(pgroot, (void *) ent->begin, ent->end - ent->begin, (void *) lakko_va_to_pa((void *) ent->begin), PERM_U | PERM_R | PERM_X);
		return;
	}

	if (ent->type == PROCMAP_TYPE_VVAR) {
		lakko_vm_map_phys(pgroot, (void *) ent->begin, ent->end - ent->begin, (void *) lakko_va_to_pa((void *) ent->begin), PERM_U | PERM_R);
		return;
	}
}

static int __setup_mappings_full(struct walnut_layout *layout)
{
	int ret;

	ret = lakko_vm_map_phys(pgroot, (void *) 0, 1UL << 32,
			      (void *) 0,
			      PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	ret = lakko_vm_map_phys(pgroot, (void *) layout->base_map, GPA_MAP_SIZE,
			      (void *) lakko_mmap_addr_to_pa((void *) layout->base_map),
			      PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	ret = lakko_vm_map_phys(pgroot, (void *) layout->base_stack, GPA_STACK_SIZE,
			      (void *) lakko_stack_addr_to_pa((void *) layout->base_stack),
			      PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	lakko_procmap_iterate(setup_vdso_cb);
	setup_vsyscall();

	return 0;
}

static int setup_mappings(bool full)
{
	struct walnut_layout layout;
	int ret = ioctl(walnut_fd, WALNUT_GET_LAYOUT, &layout);
	if (ret)
		return ret;

	phys_limit = layout.phys_limit;
	mmap_base = layout.base_map;
	stack_base = layout.base_stack;

	if (full)
		ret = __setup_mappings_full(&layout);
	else
		ret = __setup_mappings_precise();

	return ret;
}

static struct lakko_percpu *create_percpu(void)
{
	struct lakko_percpu *percpu;
	int ret;
	unsigned long fs_base;

	printf("C\n");
	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		printf("walnut: failed to get FS register\n");
		return NULL;
	}

	percpu = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (percpu == MAP_FAILED) {
		printf("MAP_FAILED\n");
		return NULL;
	}

	map_ptr(percpu, sizeof(*percpu));

        percpu->kfs_base = fs_base;
	percpu->ufs_base = fs_base;
	percpu->in_usermode = 0;

	if ((ret = setup_safe_stack(percpu))) {
		printf("setup failed\n");
		munmap(percpu, PGSIZE);
		return NULL;
	}

	return percpu;
}

static void free_percpu(struct lakko_percpu *percpu)
{
	/* XXX free stack */
	munmap(percpu, PGSIZE);
}

static void map_stack_cb(const struct lakko_procmap_entry *e)
{
	unsigned long esp;

	asm ("mov %%rsp, %0" : "=r" (esp));

	if (esp >= e->begin && esp < e->end)
		map_ptr((void*) e->begin, e->end - e->begin);
}

static void map_stack(void)
{
	lakko_procmap_iterate(map_stack_cb);
}

static int do_lakko_enter(struct lakko_percpu *percpu)
{
	struct walnut_config *conf;
	int ret;

	map_stack();

	conf = malloc(sizeof(struct walnut_config));

	conf->vcpu = 0;
	conf->rip = (__u64) &__lakko_ret;
	conf->rsp = 0;
	conf->cr3 = (physaddr_t) pgroot;
	conf->rflags = 0x2;

	/* NOTE: We don't setup the general purpose registers because __lakko_ret
	 * will restore them as they were before the __lakko_enter call */

	ret = __lakko_enter(walnut_fd, conf);
	if (ret) {
		printf("lakko: entry to Walnut mode failed, ret is %d\n", ret);
		return -EIO;
	}

	ret = lakko_boot(percpu);
	if (ret) {
		printf("lakko: problem while booting, unrecoverable\n");
		lakko_die();
	}

	return 0;
}

/**
 * on_lakko_exit - handle Walnut exits
 *
 * This function must not return. It can either exit(), __lakko_go_lakko() or
 * __lakko_go_linux().
 */
void on_lakko_exit(struct walnut_config *conf)
{
	switch (conf->ret) {
	case WALNUT_RET_EXIT:
		syscall(SYS_exit, conf->status);
	case WALNUT_RET_EPT_VIOLATION:
		printf("walnut: exit due to EPT violation\n");
		break;
	case WALNUT_RET_INTERRUPT:
		walnut_debug_handle_int(conf);
		printf("walnut: exit due to interrupt %lld\n", conf->status);
		break;
	case WALNUT_RET_SIGNAL:
		__lakko_go_lakko(walnut_fd, conf);
		break;
	case WALNUT_RET_UNHANDLED_VMEXIT:
		printf("walnut: exit due to unhandled VM exit\n");
		break;
	case WALNUT_RET_NOENTER:
		printf("walnut: re-entry to Walnut mode failed, status is %lld\n", conf->status);
		break;
	default:
		printf("walnut: unknown exit from Walnut, ret=%lld, status=%lld\n", conf->ret, conf->status);
		break;
	}

	exit(EXIT_FAILURE);
}

/**
 * lakko_enter - transitions a process to "Walnut mode"
 *
 * Can only be called after lakko_init().
 * 
 * Use this function in each forked child and/or each new thread
 * if you want to re-enter "Walnut mode".
 * 
 * Returns 0 on success, otherwise failure.
 */
int lakko_enter(void)
{
	struct lakko_percpu *percpu;
	int ret;

	printf("walnut enter\n");

	// check if this process already entered Walnut before a fork...
	if (lpercpu)
		return do_lakko_enter(lpercpu);

	printf("A\n");
	percpu = create_percpu();
	if (!percpu) {
		printf("NOMEM\n");
		return -ENOMEM;
	}

	printf("before\n");
	ret = do_lakko_enter(percpu);
	printf("after ret = %d\n", ret);
	if (ret) {
		free_percpu(percpu);
		return ret;
	}

	lpercpu = percpu;
	return 0;
}

int lakko_enter_ex(void *percpu)
{
	int ret;
	struct lakko_percpu *pcpu = (struct lakko_percpu *) percpu;
	unsigned long fs_base;

	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		printf("walnut: failed to get FS register\n");
		return -EIO;
	}

        pcpu->kfs_base = fs_base;
	pcpu->ufs_base = fs_base;
	pcpu->in_usermode = 0;

	if ((ret = setup_safe_stack(pcpu))) {
		return ret;
	}

	return do_lakko_enter(pcpu);
}

/**
 * lakko_init - initializes lakko
 * 
 * @map_full: determines if the full process address space should be mapped
 * 
 * Call this function once before using liblakko.
 *
 * Lakko supports two memory modes. If map_full is true, then every possible
 * address in the process address space is mapped. Otherwise, only addresses
 * that are used (e.g. set up through mmap) are mapped. Full mapping consumes
 * a lot of memory when enabled, but disabling it incurs slight overhead
 * since pages will occasionally need to be faulted in.
 * 
 * Returns 0 on success, otherwise failure.
 */
int lakko_init(bool map_full)
{
	int ret, i;

	BUILD_ASSERT(IOCTL_WALNUT_ENTER == WALNUT_ENTER);
	BUILD_ASSERT(WALNUT_CFG_RET == offsetof(struct walnut_config, ret));
	BUILD_ASSERT(WALNUT_CFG_RAX == offsetof(struct walnut_config, rax));
	BUILD_ASSERT(WALNUT_CFG_RBX == offsetof(struct walnut_config, rbx));
	BUILD_ASSERT(WALNUT_CFG_RCX == offsetof(struct walnut_config, rcx));
	BUILD_ASSERT(WALNUT_CFG_RDX == offsetof(struct walnut_config, rdx));
	BUILD_ASSERT(WALNUT_CFG_RSI == offsetof(struct walnut_config, rsi));
	BUILD_ASSERT(WALNUT_CFG_RDI == offsetof(struct walnut_config, rdi));
	BUILD_ASSERT(WALNUT_CFG_RSP == offsetof(struct walnut_config, rsp));
	BUILD_ASSERT(WALNUT_CFG_RBP == offsetof(struct walnut_config, rbp));
	BUILD_ASSERT(WALNUT_CFG_R8 == offsetof(struct walnut_config, r8));
	BUILD_ASSERT(WALNUT_CFG_R9 == offsetof(struct walnut_config, r9));
	BUILD_ASSERT(WALNUT_CFG_R10 == offsetof(struct walnut_config, r10));
	BUILD_ASSERT(WALNUT_CFG_R11 == offsetof(struct walnut_config, r11));
	BUILD_ASSERT(WALNUT_CFG_R12 == offsetof(struct walnut_config, r12));
	BUILD_ASSERT(WALNUT_CFG_R13 == offsetof(struct walnut_config, r13));
	BUILD_ASSERT(WALNUT_CFG_R14 == offsetof(struct walnut_config, r14));
	BUILD_ASSERT(WALNUT_CFG_R15 == offsetof(struct walnut_config, r15));
	BUILD_ASSERT(WALNUT_CFG_RIP == offsetof(struct walnut_config, rip));
	BUILD_ASSERT(WALNUT_CFG_RFLAGS == offsetof(struct walnut_config, rflags));
	BUILD_ASSERT(WALNUT_CFG_CR3 == offsetof(struct walnut_config, cr3));
	BUILD_ASSERT(WALNUT_CFG_STATUS == offsetof(struct walnut_config, status));
	BUILD_ASSERT(WALNUT_CFG_VCPU == offsetof(struct walnut_config, vcpu));

	walnut_fd = open("/dev/walnut", O_RDWR);
	if (walnut_fd <= 0) {
		printf("lakko: failed to open Walnut device\n");
		ret = -errno;
		goto fail_open;
	}

	pgroot = memalign(PGSIZE, PGSIZE);
	if (!pgroot) {
		ret = -ENOMEM;
		goto fail_pgroot;
	}
	memset(pgroot, 0, PGSIZE);

	if ((ret = walnut_page_init())) {
		printf("walnut: unable to initialize page manager\n");
		goto err;
	}

	if ((ret = setup_mappings(map_full))) {
		printf("walnut: unable to setup memory layout\n");
		goto err;
	}

	if ((ret = setup_syscall())) {
		printf("walnut: unable to setup system calls\n");
		goto err;
	}

	// disable signals for now until we have better support
	for (i = 1; i < 32; i++) {
		struct sigaction sa;

		switch (i) {
		case SIGTSTP:
		case SIGSTOP:
		case SIGKILL:
		case SIGCHLD:
		case SIGINT:
		case SIGTERM:
			continue;
		}

		memset(&sa, 0, sizeof(sa));

		sa.sa_handler = SIG_IGN;

		if (sigaction(i, &sa, NULL) == -1)
			err(1, "sigaction() %d", i);
	}

	setup_idt();

	return 0;

err:
	// FIXME: need to free memory
fail_pgroot:
	close(walnut_fd);
fail_open:
	return ret;
}

