// SPDX-License-Identifier: GPL-2.0
/*
 * spoof_cmdline.c - spoof /proc/bootconfig (SUSFS SPOOF_CMDLINE_OR_BOOTCONFIG).  boot_config_proc_show()
 * (fs/proc/bootconfig.c) does `if (saved_boot_config) seq_puts(m, saved_boot_config);`, so rewriting the static
 * pointer spoofs the whole file; that variable is a static BSS pointer resolved at load time by ksud insmod
 * (kallsyms relocation, like selinux_state in kstat) and the write is atomic, so concurrent seq reads are safe.
 * The fake string is heap-allocated (kstrdup): the supercall ABI accepts up to 8192 bytes, and the insmod
 * parameter is copied to the heap as well so a later supercall can free it safely.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_abi_path_ok */
#include "symbol_resolver.h"

/* unexported static var; ksud insmod relocates it via kallsyms */
extern char *saved_boot_config;

/* The supercall's field is 8192 wide, but this insmod parameter cannot be: module_param_string()'s value goes through a
 * sysfs attribute and a sysfs write is capped at one page, so the parameter tops out at 4095 bytes where the supercall
 * accepts 8191. */
static char param_bootconfig[4096];
module_param_string(bootconfig, param_bootconfig, sizeof(param_bootconfig), 0644);

static char *orig_boot_config;
static char *fake_boot_config;   /* heap-allocated, currently published */
static bool spoof_active;

static bool spoof_exiting;
static DEFINE_MUTEX(spoof_lock);
static void (*spoof_sync_readers_fn)(void);

/* boot_config_proc_show/seq_puts does not hold an RCU read-side lock.
 * Require the real Tasks grace period, never a timed delay. Serialising
 * publication through reclamation also bounds live old strings to one. */
static __nocfi noinline void spoof_wait_readers(void)
{
    spoof_sync_readers_fn();
}

/* Allocate first, publish second; failed requests preserve the old value. */
static int spoof_set(const char *fake)
{
    char *dup, *old;

    dup = kstrdup(fake, GFP_KERNEL);
    if (!dup)
        return -ENOMEM;

    mutex_lock(&spoof_lock);
    if (spoof_exiting || !spoof_sync_readers_fn) {
        int error = spoof_exiting ? -ESHUTDOWN : -EOPNOTSUPP;

        mutex_unlock(&spoof_lock);
        kfree(dup);
        return error;
    }
    old = fake_boot_config;
    if (!spoof_active)
        orig_boot_config = READ_ONCE(saved_boot_config);

    fake_boot_config = dup;
    WRITE_ONCE(saved_boot_config, dup);
    spoof_active = true;
    if (old) {
        spoof_wait_readers();
        kfree(old);
    }
    mutex_unlock(&spoof_lock);
    return 0;
}

bool susfs_spoof_cmdline_ready(void)
{
    return READ_ONCE(spoof_sync_readers_fn) && !READ_ONCE(spoof_exiting);
}

int susfs_spoof_cmdline_init(void)
{
    int rc;

    spoof_sync_readers_fn =
        (void *)find_kernel_symbol_exact("synchronize_rcu_tasks");
    if (!spoof_sync_readers_fn) {
        pr_warn("spoof_cmdline: no Tasks grace period; bootconfig replacement unavailable\n");
        return param_bootconfig[0] ? -EOPNOTSUPP : 0;
    }
    if (!param_bootconfig[0]) {
        SUSFS_LOGI("spoof_cmdline: no fake bootconfig, not armed\n");
        return 0;
    }

    rc = spoof_set(param_bootconfig);
    if (rc) {
        pr_err("spoof_cmdline: set failed %d, not armed\n", rc);
        return rc;
    }
    SUSFS_LOGI("spoof_cmdline armed: %s\n", param_bootconfig);
    return 0;
}

void susfs_spoof_cmdline_exit(void)
{
    char *old;

    mutex_lock(&spoof_lock);
    spoof_exiting = true;
    old = fake_boot_config;
    if (spoof_active) {
        WRITE_ONCE(saved_boot_config, orig_boot_config);
        spoof_active = false;
        orig_boot_config = NULL;
    }
    fake_boot_config = NULL;
    if (old) {
        spoof_wait_readers();
        kfree(old);
    }
    mutex_unlock(&spoof_lock);
}

/* supercall: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG */
void susfs_spoof_cmdline_supercall(void __user **arg)
{
	struct st_susfs_spoof_cmdline_or_bootconfig *info;
	int err;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		/* The kprobe has already claimed the syscall and answered 0, so returning silently leaves the
		 * caller's pre-seeded 126 (ERR_CMD_NOT_SUPPORTED) in place: the C tool then reports "please
		 * enable SUSFS in kernel" for a command this kernel implements, and ksud's err==126 check turns
		 * it into a silent success.  Upstream writes -ENOMEM here (fs/susfs.c:707-713); task_work
		 * context, so the writeback is safe. */
		err = -ENOMEM;
		if (copy_to_user(&((struct st_susfs_spoof_cmdline_or_bootconfig __user *)*arg)->err,
				 &err, sizeof(err)))
			pr_warn("cmdline supercall copy_to_user failed\n");
		pr_warn_ratelimited("spoof_cmdline: kzalloc failed, reported -ENOMEM\n");
		return;
	}

	if (copy_from_user(info, (void __user *)*arg, sizeof(*info))) {
		info->err = -EFAULT;
		goto out;
	}

	/* Empty string is rejected upstream (-EINVAL); report the real result instead of always claiming success. */
	if (!info->fake_cmdline_or_bootconfig[0]) {
		info->err = -EINVAL;
		goto out;
	}
	/* spoof_set() kstrdup()s this, i.e. strlen()s it: an unterminated fixed-size ABI field would be read past the end. */
	if (!susfs_abi_path_ok(info->fake_cmdline_or_bootconfig,
			       sizeof(info->fake_cmdline_or_bootconfig))) {
		info->err = -ENAMETOOLONG;
		goto out;
	}

	info->err = spoof_set(info->fake_cmdline_or_bootconfig);
	if (!info->err)
		SUSFS_LOGI("spoof_cmdline: set fake bootconfig (supercall)\n");
out:
	/* upstream writes back only ->err for input-type commands */
	if (copy_to_user(&((struct st_susfs_spoof_cmdline_or_bootconfig __user *)*arg)->err,
			 &info->err, sizeof(info->err)))
		pr_warn("cmdline supercall copy_to_user failed\n");
	kfree(info);
}
