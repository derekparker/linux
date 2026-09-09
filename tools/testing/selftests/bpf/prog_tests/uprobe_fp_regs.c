// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <test_progs.h>
#include "uprobe_fp_regs.skel.h"

/* System V AMD64: a -> XMM0, b -> XMM1, return -> XMM0.
 * AAPCS64: a -> V0, b -> V1, return -> V0.
 *
 * Deliberately non-static: a static function called only with compile-time
 * constants is a candidate for a .constprop clone, which would serve the
 * direct call while &trigger_fp keeps the original alive and the uprobe sits
 * on a function that never runs. External linkage discourages that rather
 * than forbidding it; the selftests build at -O0 by default, where the
 * relevant IPA passes do not run at all.
 */
noinline double trigger_fp(double a, double b)
{
	asm volatile ("");
	return a + b;
}

static __u64 as_u64(double d)
{
	union { double d; __u64 u; } v = { .d = d };

	return v.u;
}

/* Non-static for the same reason as trigger_fp() above. */
noinline double trigger_fp8(double a, double b, double c, double d,
			    double e, double f, double g, double h)
{
	asm volatile ("");
	return a + b + c + d + e + f + g + h;
}

void test_uprobe_fp_regs(void)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct uprobe_fp_regs *skel;
	ssize_t uprobe_offset;
	double a = 1.5, b = 2.25, out;

#if !defined(__x86_64__) && !defined(__i386__) && !defined(__aarch64__)
	/* bpf_get_fp_reg() is only implemented on x86 and arm64; elsewhere
	 * the kfunc is not registered at all.
	 */
	test__skip();
	return;
#endif

	uprobe_offset = get_uprobe_offset(&trigger_fp);
	if (!ASSERT_GE(uprobe_offset, 0, "uprobe_offset"))
		return;

	skel = uprobe_fp_regs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->my_pid = getpid();

	uprobe_opts.retprobe = false;
	skel->links.handle_entry = bpf_program__attach_uprobe_opts(
			skel->progs.handle_entry, getpid(), "/proc/self/exe",
			uprobe_offset, &uprobe_opts);
	if (!ASSERT_OK_PTR(skel->links.handle_entry, "attach_entry"))
		goto cleanup;

	uprobe_opts.retprobe = true;
	skel->links.handle_ret = bpf_program__attach_uprobe_opts(
			skel->progs.handle_ret, getpid(), "/proc/self/exe",
			uprobe_offset, &uprobe_opts);
	if (!ASSERT_OK_PTR(skel->links.handle_ret, "attach_ret"))
		goto cleanup;

	out = trigger_fp(a, b);
	ASSERT_EQ(as_u64(out), as_u64(a + b), "trigger_result");

	ASSERT_EQ(skel->bss->entry_rc, 8, "entry_rc");
	ASSERT_EQ(skel->bss->arg0, as_u64(a), "arg0_is_a");
	ASSERT_EQ(skel->bss->arg1, as_u64(b), "arg1_is_b");

	ASSERT_EQ(skel->bss->ret_rc, 8, "ret_rc");
	ASSERT_EQ(skel->bss->ret0, as_u64(a + b), "ret0_is_sum");

	{
		static const double in[8] = {
			1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0,
		};
		ssize_t off8;
		double sum;
		int i;

		off8 = get_uprobe_offset(&trigger_fp8);
		if (!ASSERT_GE(off8, 0, "uprobe_offset8"))
			goto cleanup;

		uprobe_opts.retprobe = false;
		skel->links.handle_entry8 = bpf_program__attach_uprobe_opts(
				skel->progs.handle_entry8, getpid(),
				"/proc/self/exe", off8, &uprobe_opts);
		if (!ASSERT_OK_PTR(skel->links.handle_entry8, "attach_entry8"))
			goto cleanup;

		sum = trigger_fp8(in[0], in[1], in[2], in[3],
				  in[4], in[5], in[6], in[7]);
		ASSERT_EQ(as_u64(sum), as_u64(255.0), "trigger8_result");

		for (i = 0; i < 8; i++) {
			char name[32];

			snprintf(name, sizeof(name), "args8_%d", i);
			ASSERT_EQ(skel->bss->args8[i], as_u64(in[i]), name);
		}

		ASSERT_EQ(skel->bss->wide_rc, 16, "wide_rc");
		/* wide[1] holds the upper 64 bits of XMM0, which System V
		 * AMD64 leaves undefined for a scalar double argument, so
		 * only wide[0] is asserted here.
		 */
		ASSERT_EQ(skel->bss->wide[0], as_u64(in[0]), "wide_low");
	}

	/* dst__sz out of {8,16} and regno out of range are both runtime-only
	 * checks: the verifier cannot constrain either at load time (dst__sz
	 * is a plain scalar arg, and regno's valid range is arch-specific),
	 * so they aren't covered by the verifier tests in
	 * progs/verifier_fp_regs.c and must be exercised here instead.
	 */
	{
		uprobe_opts.retprobe = false;
		skel->links.handle_negative = bpf_program__attach_uprobe_opts(
				skel->progs.handle_negative, getpid(),
				"/proc/self/exe", uprobe_offset, &uprobe_opts);
		if (!ASSERT_OK_PTR(skel->links.handle_negative, "attach_negative"))
			goto cleanup;

		trigger_fp(a, b);

		ASSERT_EQ(skel->data->bad_size_rc, -EINVAL, "bad_size_einval");
		ASSERT_EQ(skel->data->bad_regno_rc, -EINVAL, "bad_regno_einval");
	}

cleanup:
	uprobe_fp_regs__destroy(skel);
}
