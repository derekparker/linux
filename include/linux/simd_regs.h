/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIMD_REGS_H
#define _LINUX_SIMD_REGS_H

#include <linux/errno.h>
#include <linux/types.h>

/**
 * arch_read_user_simd_reg - Read a user-space SIMD register of current
 * @regno: architecture SIMD register number. 0-15 selects XMM0-XMM15 on
 *         x86-64; 0-31 selects V0-V31 on arm64.
 * @dst: destination buffer, at least @len bytes.
 * @len: 8 to read the low half of the register, 16 to read all of it.
 *
 * Reads the *user-space* SIMD register state of the current task. Only
 * meaningful when current entered the kernel from userspace, which is
 * always true in a uprobe handler.
 *
 * Must be called from preemptible task context: making the state available
 * involves flushing the live registers to memory, which takes locks that
 * disable softirqs. The caller is responsible for excluding hardirq and NMI
 * context and for not calling this with interrupts disabled.
 *
 * Return: number of bytes written on success, -EINVAL for a bad @regno or
 * @len, -EOPNOTSUPP if the architecture or CPU lacks support or if the
 * current task's SIMD state is not its own user state (kernel-mode SIMD in
 * flight, or a KVM guest fpstate loaded).
 */
#ifdef CONFIG_HAVE_USER_SIMD_REG_ACCESS
int arch_read_user_simd_reg(u32 regno, void *dst, u32 len);
#else
static inline int arch_read_user_simd_reg(u32 regno, void *dst, u32 len)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* _LINUX_SIMD_REGS_H */
