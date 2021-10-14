#ifndef PAL_LOCAL_H
#define PAL_LOCAL_H

// standard definitions
#define __str_t(x...)	#x
#define __str(x...)	__str_t(x)
extern int arch_prctl(int code, unsigned long *addr);

// assembly routines from lakko.S
extern int __lakko_enter(int fd, struct walnut_config *config);
extern int __lakko_ret(void);
extern void __lakko_syscall(void);
extern void __lakko_syscall_end(void);
extern void __lakko_intr(void);
extern void __lakko_go_linux(struct walnut_config *config);
extern void __lakko_go_lakko(int fd, struct walnut_config *config);

// assembly routine for handling vsyscalls
extern char __lakko_vsyscall_page;

// initialization
extern int walnut_page_init(void);

#endif
