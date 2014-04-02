/*
 * Copyright (C) 2010 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * File: evm_secfs.c
 *	- Used to signal when key is on keyring
 *	- Get the key and enable EVM
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/uaccess.h>
#include <linux/module.h>
#include "evm.h"

static struct dentry *evm_init_tpm;

/**
 * evm_read_key - read() for <securityfs>/evm
 *
 * @filp: file pointer, not actually used
 * @buf: where to put the result
 * @count: maximum to send along
 * @ppos: where to start
 *
 * If EVM_STATE_INTERFACE is enabled this should write to the userspace:
 * 0 - when EVM is disabled or uninitialized
 * 1 - when EVM is in enforce mode (initialized and enabled)
 * 2 - when EVM is in FIX mode (initialized and fix)
 * To use this interface user needs to have CAP_SYS_ADMIN
 * Notice that the param "evm=fix" has higher priority, and if it was passed
 * to the kernel then EVM will be running in FIX mode (or will be disabled).
 *
 * If EVM_STATE_INTERFACE is disabled it writes:
 * 0 - when EVM is uninitialized
 * 1 - when EVM is initialized
 *
 * Returns number of bytes read or error code, as appropriate
 */
static ssize_t evm_read_key(struct file *filp, char __user *buf,
			    size_t count, loff_t *ppos)
{
	char temp[2] = {'0', '\0'};
	ssize_t rc;

	if (*ppos != 0)
		return 0;

#ifdef CONFIG_EVM_STATE_INTERFACE
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (evm_initialized && evm_enabled)
		temp[0] += evm_fixmode ? 2 : 1;
#else  /* CONFIG_EVM_STATE_INTERFACE */
	temp[0] += evm_initialized;
#endif /* CONFIG_EVM_STATE_INTERFACE */

	rc = simple_read_from_buffer(buf, count, ppos, temp, sizeof(temp));

	return rc;
}

/**
 * evm_write_key - write() for <securityfs>/evm
 * @file: file pointer, not actually used
 * @buf: where to get the data from
 * @count: bytes sent
 * @ppos: where to start
 *
 * Used to signal that key is on the kernel key ring.
 * - get the integrity hmac key from the kernel key ring
 * - create list of hmac protected extended attributes
 * Returns number of bytes written or error code, as appropriate
 */
static ssize_t evm_write_key(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	char temp[80];
	int i;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (count >= sizeof(temp) || count == 0)
		return -EINVAL;

	if (copy_from_user(temp, buf, count) != 0)
		return -EFAULT;

	temp[count] = '\0';

	if ((sscanf(temp, "%d", &i) != 1) || ((i != 1)
#ifdef CONFIG_EVM_STATE_INTERFACE
			&& (i != 0) && (i != 2)
#endif /* CONFIG_EVM_STATE_INTERFACE */
			))
		return -EINVAL;

	if (evm_initialized == 0) {
		if (evm_init_key())
			/* If EVM cannot be initialized
			 * no more action should be taken */
			return count;
	}

	if (i == 1) {
		evm_enabled = 1;
#ifdef CONFIG_EVM_STATE_INTERFACE
		if (!evm_forcefix)
			evm_fixmode = 0;
	} else if (i == 0)
		evm_enabled = 0;
	else if (i == 2) {
		evm_enabled = 1;
		evm_fixmode = 1;
#endif /* CONFIG_EVM_STATE_INTERFACE */
	}

	return count;
}

static const struct file_operations evm_key_ops = {
	.read		= evm_read_key,
	.write		= evm_write_key,
};

int __init evm_init_secfs(void)
{
	int error = 0;

	evm_init_tpm = securityfs_create_file("evm", S_IRUSR | S_IRGRP,
					      NULL, NULL, &evm_key_ops);
	if (!evm_init_tpm || IS_ERR(evm_init_tpm))
		error = -EFAULT;

	return error;
}
