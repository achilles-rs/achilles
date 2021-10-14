#ifndef __WALNUT_COMPAT_H_
#define __WALNUT_COMPAT_H_

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#include <asm/fpu/api.h>
#else
#include <asm/i387.h>
#endif

#include <asm/desc.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#include <asm/fpu/internal.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#include <asm/fpu-internal.h>
#endif

#if !defined(VMX_EPT_AD_BIT)
#define VMX_EPT_AD_BIT          (1ull << 21)
#define VMX_EPT_AD_ENABLE_BIT   (1ull << 6)
#endif

#ifndef VMX_EPT_EXTENT_INDIVIDUAL_BIT
#define VMX_EPT_EXTENT_INDIVIDUAL_BIT           (1ull << 24)
#endif

#ifndef X86_CR4_PCIDE
#define X86_CR4_PCIDE		0x00020000 /* enable PCID support */
#endif

#ifndef SECONDARY_EXEC_ENABLE_INVPCID
#define SECONDARY_EXEC_ENABLE_INVPCID	0x00001000
#endif

#ifndef X86_CR4_FSGSBASE
#define X86_CR4_FSGSBASE	X86_CR4_RDWRGSFS
#endif

#ifndef AR_TYPE_BUSY_64_TSS
#define AR_TYPE_BUSY_64_TSS VMX_AR_TYPE_BUSY_64_TSS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static inline struct page *alloc_pages_exact_node(int nid, gfp_t gfp_mask,
                                                    unsigned int order){
	return alloc_pages_node(nid, gfp_mask, order);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
static inline unsigned long __read_cr4(void)
{
	return read_cr4();
}
static inline void cr4_set_bits(unsigned long mask)
{
	write_cr4(read_cr4() | mask);
}
static inline void cr4_clear_bits(unsigned long mask)
{
	write_cr4(read_cr4() & ~mask);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
/* 4.9.91-007 ported this commit:
 * x86/mm: Split read_cr3() into read_cr3_pa() and __read_cr3()
 */
static inline unsigned long read_cr3(void)
{
	return __read_cr3();
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,91) && defined(TIF_NEED_FPU_LOAD)
/* 4.9.91-009 ported this patchset: https://lkml.org/lkml/2019/4/3/877.
 * Like ret-to-userspace, ret-to-guest shall take care it similarly.
 * Refer to 4.19.91-009/arch/x86/kvm/x86.c:7771.
 */
static inline void compat_fpu_restore(void)
{
	if (test_thread_flag(TIF_NEED_FPU_LOAD))
		switch_fpu_return();
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static inline void compat_fpu_restore(void)
{
	if (!current->thread.fpu.initialized)
		fpu__restore(&current->thread.fpu);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
static inline void compat_fpu_restore(void)
{
	if (!current->thread.fpu.fpregs_active)
		fpu__restore(&current->thread.fpu);
}
#else
static inline void compat_fpu_restore(void)
{
	if (!__thread_has_fpu(current))
		math_state_restore();
}
#endif

#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
static inline void compat_fpu_restore(void)
{
	if (!current->thread.fpu.fpregs_active)
		fpu__restore(&current->thread.fpu);
}
#else
static inline void compat_fpu_restore(void)
{
	if (!__thread_has_fpu(current))
		math_state_restore();
}
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define _PAGE_CACHE_MODE_WB _PAGE_CACHE_WB
#define _PAGE_CACHE_MODE_WC _PAGE_CACHE_WC
static inline long pgprot2cachemode(pgprot_t pgprot)
{
	return pgprot_val(pgprot) & _PAGE_CACHE_MASK;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
/*
 * Commit 87930019c713 ("x86/paravirt: Remove no longer used paravirt functions").
 */
static inline void native_store_idt(struct desc_ptr *dtr)
{
	store_idt(dtr);
}
#endif

#ifdef VMX_EPT_DEFAULT_MT
#define WALNUT_VMX_EPT_DEFAULT (VMX_EPT_DEFAULT_MT | \
				VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT)
#else
#define WALNUT_VMX_EPT_DEFAULT (VMX_EPTP_MT_WB | VMX_EPTP_PWL_4)
#endif

#ifndef VMX_EPT_AD_ENABLE_BIT
#define VMX_EPT_AD_ENABLE_BIT VMX_EPTP_AD_ENABLE_BIT
#endif

#endif /* __WALNUT_COMPAT_H_ */
