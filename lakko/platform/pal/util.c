/*
 * util.c - this file is for random utilities and hypervisor backdoors
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <stdbool.h>

#include "lakko.h"

static int lakko_puts(const char *buf)
{
	long ret;

	asm volatile("movq $1, %%rax \n\t" // SYS_write
	    "movq $1, %%rdi \n\t" // STDOUT
	    "movq %1, %%rsi \n\t" // string
	    "movq %2, %%rdx \n\t" // string len
	    "vmcall \n\t"
	    "movq %%rax, %0 \n\t" :
	    "=r" (ret) : "r" (buf), "r" (strlen(buf)) :
	    "rax", "rdi", "rsi", "rdx");

	return ret;
}

/**
 * walnut_printf - a raw low-level printf request that uses a hypercall directly
 * 
 * This is intended for working around libc syscall issues.
 */
int walnut_printf(const char *fmt, ...)
{
	va_list args;
	char buf[1024];

	va_start(args, fmt);

	vsprintf(buf, fmt, args);

	return lakko_puts(buf);
}

void * lakko_mmap(void *addr, size_t length, int prot,
	     int flags, int fd, off_t offset)
{
	void *ret_addr;

	asm volatile("movq $9, %%rax \n\t" // SYS_mmap
	    "movq %1, %%rdi \n\t"
	    "movq %2, %%rsi \n\t"
	    "movl %3, %%edx \n\t"
	    "movq %4, %%r10 \n\t"
	    "movq %5, %%r8 \n\t"
	    "movq %6, %%r9 \n\t"
	    "vmcall \n\t"
	    "movq %%rax, %0 \n\t" :
	    "=r" ((unsigned long) ret_addr) : "r" ((unsigned long) addr), "r" (length),
	    "r" (prot), "r" ((unsigned long) flags), "r" ((unsigned long) fd),
	    "r" ((unsigned long) offset) : "rax", "rdi", "rsi", "rdx");

	return ret_addr;
}

/**
 * lakko_die - kills the Lakko process immediately
 *
 */
void lakko_die(void)
{
	asm volatile("movq $60, %rax\n" // exit
		     "vmcall\n");
}

/**
 * lakko_passthrough_syscall - makes a syscall using the args of a trap frame
 *
 * @tf: the trap frame to apply
 * 
 * sets the return code in tf->rax
 */
void lakko_passthrough_syscall(struct lakko_tf *tf)
{
	asm volatile("movq %2, %%rdi \n\t"
		     "movq %3, %%rsi \n\t"
		     "movq %4, %%rdx \n\t"
		     "movq %5, %%r10 \n\t"
		     "movq %6, %%r8 \n\t"
		     "movq %7, %%r9 \n\t"
		     "vmcall \n\t"
		     "movq %%rax, %0 \n\t" :
		     "=a" (tf->rax) :
		     "a" (tf->rax), "r" (tf->rdi), "r" (tf->rsi),
		     "r" (tf->rdx), "r" (tf->rcx), "r" (tf->r8),
		     "r" (tf->r9) : "rdi", "rsi", "rdx", "r10",
		     "r8", "r9", "memory");     
}

sighandler_t lakko_signal(int sig, sighandler_t cb)
{
	lakko_intr_cb x = (lakko_intr_cb) cb; /* XXX */

	if (signal(sig, cb) == SIG_ERR)
		return SIG_ERR;

	lakko_register_intr_handler(WALNUT_SIGNAL_INTR_BASE + sig, x);

	return NULL;
}

void lakko_control_guest_ints(bool enable)
{
	asm("vmcall" : : "a" (VMCALL_CONTROL_GUEST_INTS), "b" (enable));
}
