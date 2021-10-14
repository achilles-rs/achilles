#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/perf_event.h>
#include <asm/uaccess.h>

#include "walnut.h"
#include "vmx.h"
#include "preempttrap.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A driver for achilles");

static int walnut_is_in_guest(void)
{
	return __this_cpu_read(local_vcpu) != NULL;
}

static int walnut_is_user_mode(void)
{
        return 0;
}

static unsigned long walnut_get_guest_ip(void)
{
	unsigned long long ip = 0;
	if (__this_cpu_read(local_vcpu))
		ip = vmcs_readl(GUEST_RIP);
	return ip;
}

static struct perf_guest_info_callbacks walnut_guest_cbs = {
        .is_in_guest            = walnut_is_in_guest,
        .is_user_mode           = walnut_is_user_mode,
        .get_guest_ip           = walnut_get_guest_ip,
};

static int walnut_enter(struct walnut_config *conf, int64_t *ret)
{
	return vmx_launch(conf, ret);
}

static long walnut_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	long r = -EINVAL;
	struct walnut_config conf;
	struct walnut_layout layout;

	switch (ioctl) {
	case WALNUT_ENTER:
		r = copy_from_user(&conf, (int __user *) arg,
				   sizeof(struct walnut_config));
		if (r) {
			r = -EIO;
			goto out;
		}

		r = walnut_enter(&conf, &conf.ret);
		if (r)
			break;

		r = copy_to_user((void __user *)arg, &conf,
				 sizeof(struct walnut_config));
		if (r) {
			r = -EIO;
			goto out;
		}
		break;

	case WALNUT_GET_SYSCALL:
		rdmsrl(MSR_LSTAR, r);
		printk(KERN_INFO "R %lx\n", (unsigned long) r);
		break;

	case WALNUT_GET_LAYOUT:
		layout.phys_limit = (1UL << boot_cpu_data.x86_phys_bits);
		layout.base_map = LG_ALIGN(current->mm->mmap_base) - GPA_MAP_SIZE;
		layout.base_stack = LG_ALIGN(current->mm->start_stack) - GPA_STACK_SIZE;
		r = copy_to_user((void __user *)arg, &layout,
				 sizeof(struct walnut_layout));
		if (r) {
			r = -EIO;
			goto out;
		}
		break;

	case WALNUT_TRAP_ENABLE:
		r = walnut_trap_enable(arg);
		break;

	case WALNUT_TRAP_DISABLE:
		r = walnut_trap_disable(arg);
		break;

	default:
		return -ENOTTY;
	}

out:
	return r;
}

static int walnut_dev_release(struct inode *inode, struct file *file)
{
	vmx_cleanup();
	return 0;
}

static const struct file_operations walnut_chardev_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= walnut_dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= walnut_dev_ioctl,
#endif
	.llseek		= noop_llseek,
	.release	= walnut_dev_release,
};

static struct miscdevice walnut_dev = {
	WALNUT_MINOR,
	"walnut",
	&walnut_chardev_ops,
};

static int __init walnut_init(void)
{
	int r;
	perf_register_guest_info_callbacks(&walnut_guest_cbs);

	printk(KERN_ERR "walnut module loaded\n");

	if ((r = vmx_init())) {
		printk(KERN_ERR "walnut: failed to initialize vmx\n");
		return r;
	}

	r = misc_register(&walnut_dev);
	if (r) {
		printk(KERN_ERR "walnut: misc device register failed\n");
		vmx_exit();
	}

	return r;
}

static void __exit walnut_exit(void)
{
	perf_unregister_guest_info_callbacks(&walnut_guest_cbs);
	misc_deregister(&walnut_dev);
	vmx_exit();
}

module_init(walnut_init);
module_exit(walnut_exit);
