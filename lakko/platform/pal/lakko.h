#pragma once

#include <sys/queue.h>
#include <stdbool.h>

#include "mmu.h"
#include "elf.h"
#include "fpu.h"
#include "../../../driver/kern/walnut.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*sighandler_t)(int);

// utilities

static inline unsigned long lakko_get_ticks(void)
{
	unsigned int a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((unsigned long) a) | (((unsigned long) d) << 32);
}

extern int walnut_printf(const char *fmt, ...);
extern void lakko_die(void);
extern void * lakko_mmap(void *addr, size_t length, int prot,
		       int flags, int fd, off_t offset);
extern sighandler_t lakko_signal(int sig, sighandler_t cb);
extern unsigned long lakko_get_user_fs(void);
extern void lakko_set_user_fs(unsigned long fs_base);

#ifndef assert
#define assert(expr) \
if (!(expr)) { \
	walnut_printf("ASSERT(" #expr ") at %s:%d in function %s\n", \
			   __FILE__, __LINE__, __func__); \
	lakko_die(); \
}
#endif /* assert */

// fault handling

/*
 * We use the same general GDT layout as Linux so that can we use
 * the same syscall MSR values. In practice only code segments
 * matter, since ia-32e mode ignores most of segment values anyway,
 * but just to be extra careful we match data as well.
 */
#define GD_KT		0x10
#define GD_KD		0x18
#define GD_UD		0x28
#define GD_UT		0x30
#define GD_TSS		0x38
#define GD_TSS2		0x40
#define NR_GDT_ENTRIES	9

struct lakko_tf {
	/* manually saved, arguments */
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;

	/* saved by C calling conventions */
	uint64_t rbx;
	uint64_t rbp;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

	/* system call number, ret */
	uint64_t rax;

	/* exception frame */
	uint32_t err;
	uint32_t pad1;
	uint64_t rip;
	uint16_t cs;
	uint16_t pad2[3];
	uint64_t rflags;
	uint64_t rsp;
	uint16_t ss;
	uint16_t pad3[3];
} __attribute__((packed));

#define ARG0(tf)        ((tf)->rdi)
#define ARG1(tf)        ((tf)->rsi)
#define ARG2(tf)        ((tf)->rdx)
#define ARG3(tf)        ((tf)->rcx)
#define ARG4(tf)        ((tf)->r8)
#define ARG5(tf)        ((tf)->r9)

typedef void (*lakko_intr_cb) (struct lakko_tf *tf);
typedef void (*lakko_pgflt_cb) (uintptr_t addr, uint64_t fec,
			      struct lakko_tf *tf);
typedef void (*lakko_syscall_cb) (struct lakko_tf *tf);

#define WALNUT_SIGNAL_INTR_BASE 200

extern int lakko_register_intr_handler(int vec, lakko_intr_cb cb);
extern int lakko_register_signal_handler(int signum, lakko_intr_cb cb);
extern void lakko_register_pgflt_handler(lakko_pgflt_cb cb);
extern void lakko_register_syscall_handler(lakko_syscall_cb cb);

extern void lakko_pop_trap_frame(struct lakko_tf *tf);
extern int lakko_jump_to_user(struct lakko_tf *tf);
extern void lakko_ret_from_user(int ret)  __attribute__ ((noreturn));
extern void lakko_dump_trap_frame(struct lakko_tf *tf);
extern void lakko_passthrough_syscall(struct lakko_tf *tf);

// page allocation

SLIST_HEAD(page_head, page);
typedef SLIST_ENTRY(page) page_entry_t;

struct page {
	page_entry_t link;
	uint64_t ref;
};

extern struct page *pages;
extern int num_pages;

#define PAGEBASE	0x200000000
#define MAX_PAGES	(1ul << 20) /* 4 GB of memory */

extern struct page * walnut_page_alloc(void);
extern void walnut_page_free(struct page *pg);
extern void walnut_page_stats(void);

static inline struct page * lakko_pa2page(physaddr_t pa)
{
	return &pages[PPN(pa - PAGEBASE)];
}

static inline physaddr_t lakko_page2pa(struct page *pg)
{
	return PAGEBASE + ((pg - pages) << PGSHIFT);
}

extern bool lakko_page_isfrompool(physaddr_t pa);

static inline struct page * walnut_page_get(struct page *pg)
{
	assert(pg >= pages);
	assert(pg < (pages + num_pages));

	pg->ref++;

	return pg;
}

static inline void lakko_page_put(struct page *pg)
{
	assert(pg >= pages);
	assert(pg < (pages + num_pages));

	pg->ref--;

	if (!pg->ref)
		walnut_page_free(pg);
}

// virtual memory

extern ptent_t *pgroot;
extern uintptr_t phys_limit;
extern uintptr_t mmap_base;
extern uintptr_t stack_base;

#define APIC_BASE 0xfffffffffffff000

static inline uintptr_t lakko_mmap_addr_to_pa(void *ptr)
{
	return ((uintptr_t) ptr) - mmap_base +
		phys_limit - GPA_STACK_SIZE - GPA_MAP_SIZE;
}

static inline uintptr_t lakko_stack_addr_to_pa(void *ptr)
{
	return ((uintptr_t) ptr) - stack_base +
		phys_limit - GPA_STACK_SIZE;
}

static inline uintptr_t lakko_va_to_pa(void *ptr)
{
	if (PGADDR(ptr) == APIC_BASE)
		return GPA_APIC_PAGE;
	else if ((uintptr_t) ptr >= stack_base)
		return lakko_stack_addr_to_pa(ptr);
	else if ((uintptr_t) ptr >= mmap_base)
		return lakko_mmap_addr_to_pa(ptr);
	else
		return (uintptr_t) ptr;
}

#define PERM_NONE  	0	/* no access */
#define PERM_R		0x0001	/* read permission */
#define PERM_W		0x0002	/* write permission */
#define PERM_X		0x0004	/* execute permission */
#define PERM_U		0x0008	/* user-level permission */
#define PERM_UC		0x0010  /* make uncachable */
#define PERM_COW	0x0020	/* COW flag */
#define PERM_USR1	0x1000  /* User flag 1 */
#define PERM_USR2	0x2000  /* User flag 2 */
#define PERM_USR3	0x3000  /* User flag 3 */
#define PERM_BIG	0x0100	/* Use large pages */
#define PERM_BIG_1GB	0x0200	/* Use large pages (1GB) */

// Helper Macros
#define PERM_SCODE	(PERM_R | PERM_X)
#define PERM_STEXT	(PERM_R | PERM_W)
#define PERM_SSTACK	PERM_STEXT
#define PERM_UCODE	(PERM_R | PERM_U | PERM_X)
#define PERM_UTEXT	(PERM_R | PERM_U | PERM_W)
#define PERM_USTACK	PERM_UTEXT

static inline void lakko_flush_tlb_one(unsigned long addr)
{
	asm ("invlpg (%0)" :: "r" (addr) : "memory");
}

static inline void lakko_flush_tlb(void)
{
	asm ("mov %%cr3, %%rax\n"
	     "mov %%rax, %%cr3\n" ::: "rax");
}

#define CR3_NOFLUSH	(1UL << 63)

static inline void load_cr3(unsigned long cr3)
{       
        asm("mov %%rax, %%cr3\n" : : "a" (cr3));
}

static inline void __invpcid(int mode, unsigned long addr)
{
	struct {
		unsigned long eptp, gpa;
	} operand = {1, addr};
	asm volatile("invpcid (%%rax), %%rcx" ::
		     "a" (&operand), "c" (mode) : "cc", "memory");
}

/* Define beginning and end of VA space */
#define VA_START		((void *)0)
#define VA_END			((void *)-1)

enum {
	CREATE_NONE = 0,
	CREATE_NORMAL = 1,
	CREATE_BIG = 2,
	CREATE_BIG_1GB = 3,
};

extern int lakko_vm_mprotect(ptent_t *root, void *va, size_t len, int perm);
extern int lakko_vm_map_phys(ptent_t *root, void *va, size_t len, void *pa, int perm);
extern int lakko_vm_map_pages(ptent_t *root, void *va, size_t len, int perm);
extern void lakko_vm_unmap(ptent_t *root, void *va, size_t len);
extern int lakko_vm_lookup(ptent_t *root, void *va, int create, ptent_t **pte_out);

extern int lakko_vm_insert_page(ptent_t *root, void *va, struct page *pg, int perm);
extern struct page * lakko_vm_lookup_page(ptent_t *root, void *va);

extern ptent_t * lakko_vm_clone(ptent_t *root);
extern void lakko_vm_free(ptent_t *root);
extern void lakko_vm_default_pgflt_handler(uintptr_t addr, uint64_t fec);

typedef int (*page_walk_cb)(const void *arg, ptent_t *ptep, void *va);
extern int lakko_vm_page_walk(ptent_t *root, void *start_va, void *end_va,
			    page_walk_cb cb, const void *arg);

// process memory maps

#define PROCMAP_TYPE_UNKNOWN	0x00
#define PROCMAP_TYPE_FILE	0x01
#define PROCMAP_TYPE_ANONYMOUS	0x02
#define PROCMAP_TYPE_HEAP	0x03
#define PROCMAP_TYPE_STACK	0x04
#define PROCMAP_TYPE_VSYSCALL	0x05
#define PROCMAP_TYPE_VDSO	0x06
#define PROCMAP_TYPE_VVAR	0x07

struct lakko_procmap_entry {
	uintptr_t	begin;
	uintptr_t	end;
	uint64_t	offset;
	bool		r; // Readable
	bool		w; // Writable
	bool		x; // Executable
	bool		p; // Private (or shared)
	char		*path;
	int		type;
};

typedef void (*lakko_procmap_cb)(const struct lakko_procmap_entry *);

extern void lakko_procmap_iterate(lakko_procmap_cb cb);
extern void lakko_procmap_dump();

// elf helper functions

struct lakko_elf {
	int		fd;
	unsigned char	*mem;
	int		len;
	Elf64_Ehdr	hdr;
	Elf64_Phdr	*phdr;
	Elf64_Shdr	*shdr;
	char		*shdrstr;
	void		*priv;
};

typedef int (*lakko_elf_phcb)(struct lakko_elf *elf, Elf64_Phdr *phdr);
typedef int (*lakko_elf_shcb)(struct lakko_elf *elf, const char *sname,
		                     int snum, Elf64_Shdr *shdr);

extern int lakko_elf_open(struct lakko_elf *elf, const char *path);
extern int lakko_elf_open_mem(struct lakko_elf *elf, void *mem, int len);
extern int lakko_elf_close(struct lakko_elf *elf);
extern int lakko_elf_dump(struct lakko_elf *elf);
extern int lakko_elf_iter_sh(struct lakko_elf *elf, lakko_elf_shcb cb);
extern int lakko_elf_iter_ph(struct lakko_elf *elf, lakko_elf_phcb cb);
extern int lakko_elf_load_ph(struct lakko_elf *elf, Elf64_Phdr *phdr, off_t off);

// entry routines

extern int lakko_init(bool map_full);
extern int lakko_enter();

/**
 * lakko_init_and_enter - initializes liblakko and enters "Lakko mode"
 * 
 * This is a simple initialization routine that handles everything
 * in one go. Note that you still need to call lakko_enter() in
 * each new forked child or thread.
 * 
 * Returns 0 on success, otherwise failure.
 */
static inline int lakko_init_and_enter(void)
{
	int ret;

	if ((ret = lakko_init(1))) {
		return ret;
	}

	return lakko_enter();
}

extern void lakko_control_guest_ints(bool enable);

#ifdef __cplusplus
}
#endif