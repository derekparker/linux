// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern int bpf_get_fp_reg(void *dst, __u32 dst__sz, __u32 regno) __ksym;

SEC("uprobe")
__description("bpf_get_fp_reg: 8-byte read into 8-byte buffer")
__success
int fp_reg_ok8(void *ctx)
{
	__u64 v = 0;

	bpf_get_fp_reg(&v, sizeof(v), 0);
	return 0;
}

SEC("uprobe")
__description("bpf_get_fp_reg: 16-byte read into 16-byte buffer")
__success
int fp_reg_ok16(void *ctx)
{
	__u64 v[2] = {};

	bpf_get_fp_reg(&v[0], sizeof(v), 0);
	return 0;
}

SEC("uprobe")
__description("bpf_get_fp_reg: size larger than buffer is rejected")
__failure __msg("R1 and R2 memory, len pair leads to invalid memory access")
int fp_reg_overflow(void *ctx)
{
	__u64 v = 0;

	/* claims 16 bytes but the buffer is 8 */
	bpf_get_fp_reg(&v, 16, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
