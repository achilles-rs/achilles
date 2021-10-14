/*
 * trap.c - x86 fault handling
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>

#include "lakko.h"
#include "cpu-x86.h"
#include "../../../driver/kern/walnut.h"

static lakko_syscall_cb syscall_cb;
static lakko_pgflt_cb pgflt_cb;
static lakko_intr_cb intr_cbs[IDT_ENTRIES];

static inline unsigned long read_cr2(void)
{
	unsigned long val;
	asm volatile("mov %%cr2, %0\n\t" : "=r" (val));
	return val;
}

int lakko_register_intr_handler(int vec, lakko_intr_cb cb)
{
	if (vec >= IDT_ENTRIES || vec < 0)
		return -EINVAL;

	intr_cbs[vec] = cb;
	return 0;
}

int lakko_register_signal_handler(int signum, lakko_intr_cb cb)
{
	return lakko_register_intr_handler(WALNUT_SIGNAL_INTR_BASE + signum, cb);
}

void lakko_register_syscall_handler(lakko_syscall_cb cb)
{
	syscall_cb = cb;
}

void lakko_register_pgflt_handler(lakko_pgflt_cb cb)
{
	pgflt_cb = cb;
}

static bool addr_is_mapped(void *va)
{
	int ret;
	ptent_t *pte;

	ret = lakko_vm_lookup(pgroot, va, CREATE_NONE, &pte);
	if (ret)
		return 0;

	if (!(*pte & PTE_P))
		return 0;

	return 1;
}

#define STACK_DEPTH 12

static void lakko_dump_stack(struct lakko_tf *tf)
{
	int i;
	unsigned long *sp = (unsigned long *) tf->rsp;

	// we use walnut_printf() because this might
	// have to work even if libc doesn't.
	walnut_printf("walnut: Dumping Stack Contents...\n");
	for (i = 0; i < STACK_DEPTH; i++) {
		if (!addr_is_mapped(&sp[i])) {
			walnut_printf("walnut: reached unmapped addr\n");
			break;
		}
		walnut_printf("walnut: RSP%+-3d 0x%016lx\n", i * sizeof(long),
			   sp[i]);
	}
}

static void lakko_hexdump(void *x, int len)
{
	unsigned char *p = x;

	while (len--)
		walnut_printf("%.2x ", *p++);

	walnut_printf("\n");
}

static void dump_ip(struct lakko_tf *tf)
{
	unsigned char *p = (void*) tf->rip;
	int len = 20;

	walnut_printf("walnut: code before IP\t");
	lakko_hexdump(p - len, len);

	walnut_printf("walnut: code at IP\t");
	lakko_hexdump(p, len);
}

void lakko_dump_trap_frame(struct lakko_tf *tf)
{
	// we use walnut_printf() because this might
	// have to work even if libc doesn't.
	walnut_printf("walnut: --- Begin Trap Dump ---\n");
	walnut_printf("walnut: RIP 0x%016llx\n", tf->rip);
	walnut_printf("walnut: CS 0x%02x SS 0x%02x\n", tf->cs, tf->ss);
	walnut_printf("walnut: ERR 0x%08lx RFLAGS 0x%08lx\n", tf->err, tf->rflags);
	walnut_printf("walnut: RAX 0x%016lx RCX 0x%016lx\n", tf->rax, tf->rcx);
	walnut_printf("walnut: RDX 0x%016lx RBX 0x%016lx\n", tf->rdx, tf->rbx);
	walnut_printf("walnut: RSP 0x%016lx RBP 0x%016lx\n", tf->rsp, tf->rbp);
	walnut_printf("walnut: RSI 0x%016lx RDI 0x%016lx\n", tf->rsi, tf->rdi);
	walnut_printf("walnut: R8  0x%016lx R9  0x%016lx\n", tf->r8, tf->r9);
	walnut_printf("walnut: R10 0x%016lx R11 0x%016lx\n", tf->r10, tf->r11);
	walnut_printf("walnut: R12 0x%016lx R13 0x%016lx\n", tf->r12, tf->r13);
	walnut_printf("walnut: R14 0x%016lx R15 0x%016lx\n", tf->r14, tf->r15);
	lakko_dump_stack(tf);
	dump_ip(tf);
	walnut_printf("walnut: --- End Trap Dump ---\n");
}

void lakko_syscall_handler(struct lakko_tf *tf)
{
	if (syscall_cb) {
		syscall_cb(tf);
	} else {
		walnut_printf("missing handler for system call - #%d\n", tf->rax);
		lakko_dump_trap_frame(tf);
		lakko_die();
	}
}

void lakko_trap_handler(int num, struct lakko_tf *tf)
{
	if (intr_cbs[num]) {
		intr_cbs[num](tf);
		return;
	}

	switch (num) {
	case T_PGFLT:
		if (pgflt_cb) {
			pgflt_cb(read_cr2(), tf->err, tf);
		} else {
			walnut_printf("unhandled page fault %lx %lx\n",
				   read_cr2(), tf->err);
			lakko_dump_trap_frame(tf);
			lakko_procmap_dump();
			lakko_die();
		}
		break;

	case T_NMI:
	case T_DBLFLT:
	case T_GPFLT:
		walnut_printf("fatal exception %d, code %lx - dying...\n",
			   num, tf->err);
		lakko_dump_trap_frame(tf);
		lakko_die();
		break;

	case 32 ... 255:
		asm("vmcall": : "a" (VMCALL_INTERRUPT));
		break;

	default:
		walnut_printf("unhandled exception %d\n", num);
		lakko_dump_trap_frame(tf);
		lakko_die();
	}
}
