#pragma once

#ifndef __ASSEMBLY__

#include <linux/types.h>

/*
 * IOCTL interface
 */

/* FIXME: this must be reserved in miscdevice.h */
#define WALNUT_MINOR       233

#define WALNUT_ENTER	_IOR(WALNUT_MINOR, 0x01, struct walnut_config)
#define WALNUT_GET_SYSCALL _IO(WALNUT_MINOR, 0x02)
#define WALNUT_GET_LAYOUT	_IOW(WALNUT_MINOR, 0x03, struct walnut_layout)
#define WALNUT_TRAP_ENABLE _IOR(WALNUT_MINOR, 0x04, struct walnut_trap_config)
#define WALNUT_TRAP_DISABLE _IO(WALNUT_MINOR, 0x05)

#define WALNUT_SIGNAL_INTR_BASE 200

struct walnut_config {
	__s64 ret;
	__u64 rax;
	__u64 rbx;
	__u64 rcx;
	__u64 rdx;
	__u64 rsi;
	__u64 rdi;
	__u64 rsp;
	__u64 rbp;
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 rip;
	__u64 rflags;
	__u64 cr3;
	__s64 status;
	__u64 vcpu;
} __attribute__((packed));

struct walnut_layout {
	__u64 phys_limit;
	__u64 base_map;
	__u64 base_stack;
} __attribute__((packed));

struct walnut_trap_regs {
	__u64 rax;
	__u64 rbx;
	__u64 rcx;
	__u64 rdx;
	__u64 rsi;
	__u64 rdi;
	__u64 rsp;
	__u64 rbp;
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 rip;
	__u64 rflags;
} __attribute__((packed));

typedef void (* walnut_trap_notify_func)(struct walnut_trap_regs *, void *);

struct walnut_trap_config {
	__u64 trigger_rip;
	walnut_trap_notify_func notify_func;
	struct walnut_trap_regs *regs;
	__u64 regs_size;
	void *priv;
	__u8 delay;
} __attribute__((packed));

#define GPA_STACK_SIZE	((unsigned long) 1 << 30) /* 1 gigabyte */
#define GPA_MAP_SIZE   (((unsigned long) 1 << 36) - GPA_STACK_SIZE) /* 63 gigabytes */
#define LG_ALIGN(addr)	((addr + (1 << 30) - 1) & ~((1 << 30) - 1))

/* FIXME: magic page that maps to APIC of the host */
#define GPA_APIC_PAGE ((1ul<<46)-4096)

#endif /* __ASSEMBLY__ */

#define IOCTL_WALNUT_ENTER 0x80b0e901

#define WALNUT_CFG_RET 0x00
#define WALNUT_CFG_RAX 0x08
#define WALNUT_CFG_RBX 0x10
#define WALNUT_CFG_RCX 0x18
#define WALNUT_CFG_RDX 0x20
#define WALNUT_CFG_RSI 0x28
#define WALNUT_CFG_RDI 0x30
#define WALNUT_CFG_RSP 0x38
#define WALNUT_CFG_RBP 0x40
#define WALNUT_CFG_R8 0x48
#define WALNUT_CFG_R9 0x50
#define WALNUT_CFG_R10 0x58
#define WALNUT_CFG_R11 0x60
#define WALNUT_CFG_R12 0x68
#define WALNUT_CFG_R13 0x70
#define WALNUT_CFG_R14 0x78
#define WALNUT_CFG_R15 0x80
#define WALNUT_CFG_RIP 0x88
#define WALNUT_CFG_RFLAGS 0x90
#define WALNUT_CFG_CR3 0x98
#define WALNUT_CFG_STATUS 0xa0
#define WALNUT_CFG_VCPU 0xa8

#define WALNUT_RET_EXIT 1
#define WALNUT_RET_EPT_VIOLATION 2
#define WALNUT_RET_INTERRUPT 3
#define WALNUT_RET_SIGNAL 4
#define WALNUT_RET_UNHANDLED_VMEXIT 5
#define WALNUT_RET_NOENTER 6

#define VMCALL_START 0x1000
#define VMCALL_CONTROL_GUEST_INTS 0x1000
#define VMCALL_INTERRUPT 0x1001
