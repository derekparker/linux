// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern int bpf_get_fp_reg(void *dst, __u32 dst__sz, __u32 regno) __weak __ksym;

int my_pid = 0;

__u64 arg0 = 0;
__u64 arg1 = 0;
__u64 ret0 = 0;
int entry_rc = 0;
int ret_rc = 0;

SEC("uprobe")
int BPF_UPROBE(handle_entry)
{
	if ((bpf_get_current_pid_tgid() >> 32) != my_pid)
		return 0;

	entry_rc = bpf_get_fp_reg(&arg0, sizeof(arg0), 0);
	bpf_get_fp_reg(&arg1, sizeof(arg1), 1);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(handle_ret)
{
	if ((bpf_get_current_pid_tgid() >> 32) != my_pid)
		return 0;

	ret_rc = bpf_get_fp_reg(&ret0, sizeof(ret0), 0);
	return 0;
}

__u64 args8[8] = {};
__u64 wide[2] = {};
int wide_rc = 0;

SEC("uprobe")
int BPF_UPROBE(handle_entry8)
{
	if ((bpf_get_current_pid_tgid() >> 32) != my_pid)
		return 0;

	bpf_get_fp_reg(&args8[0], 8, 0);
	bpf_get_fp_reg(&args8[1], 8, 1);
	bpf_get_fp_reg(&args8[2], 8, 2);
	bpf_get_fp_reg(&args8[3], 8, 3);
	bpf_get_fp_reg(&args8[4], 8, 4);
	bpf_get_fp_reg(&args8[5], 8, 5);
	bpf_get_fp_reg(&args8[6], 8, 6);
	bpf_get_fp_reg(&args8[7], 8, 7);

	wide_rc = bpf_get_fp_reg(&wide[0], 16, 0);
	return 0;
}

/* Sentinel: bpf_get_fp_reg() never returns 1 (its results are byte counts
 * 8/16 on success, or negative errno on failure), so 1 unambiguously means
 * "the program has not run yet / did not overwrite this".
 *
 * Note the non-zero initialiser puts these in .data rather than .bss, so the
 * userspace side reads them via skel->data->, not skel->bss->.
 */
int bad_size_rc = 1;
int bad_regno_rc = 1;

SEC("uprobe")
int BPF_UPROBE(handle_negative)
{
	__u64 buf[2] = {};

	if ((bpf_get_current_pid_tgid() >> 32) != my_pid)
		return 0;

	/* dst__sz (4) is not in {8, 16}: -EINVAL is validated at runtime by
	 * the kfunc itself, not by the verifier, which only requires the
	 * buffer to be at least dst__sz bytes. buf is shared with the regno
	 * call below, which asks for 8.
	 */
	bad_size_rc = bpf_get_fp_reg(&buf[0], 4, 0);

	/* regno (99) is out of range: -EINVAL is validated at runtime by
	 * arch code. dst__sz matches the buffer so only regno is wrong.
	 */
	bad_regno_rc = bpf_get_fp_reg(&buf[0], 8, 99);

	return 0;
}
