// SPDX-License-Identifier: GPL-2.0
/*
 * Host-side test for the matching rule in tools/susfs_insmod.c.
 *
 * The rule that matters: a name is only ever taken from a record that belongs to the
 * KERNEL.  /proc/kallsyms prints the kernel's own symbols first and the loaded modules'
 * afterwards, and a module record carries a fourth field, " [module]".  That address is
 * inside another module's image, so adopting it would resolve our import to a stranger's
 * symbol - same name, unrelated meaning - and the load would come up as the wrong thing
 * instead of failing.  Measured on 5.10: `__stack_chk_guard` is exactly that case (a
 * kernelsu.ko symbol), and taking it is what made our 5.10 images load "successfully"
 * with a stack guard belonging to another module - see the fix that turned the protector
 * off below 5.11.
 *
 * Build and run (the CI tools job does this):
 *   cc -O1 -o /tmp/insmod_match_test tools/insmod_match_test.c && /tmp/insmod_match_test
 *
 * The test includes the loader so it can drive ks_record() directly: that function is the
 * whole rule, it is pure (a line of text plus the undefined-symbol table), and the loader
 * is written to be built off-device (SUSFS_INSMOD_HOSTTEST skips the _start block).
 */
#include <stdio.h>
#include <string.h>

#define SUSFS_INSMOD_HOSTTEST 1
#include "susfs_insmod.c"

/* Nothing here is supposed to reach an actual syscall. */
sysarg sys6(sysarg n, sysarg a, sysarg b, sysarg c, sysarg d, sysarg e, sysarg f)
{
	(void)n; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
	return -1;
}

static int failures;
static struct elf64_sym the_sym;
static u32 matched;

static void feed(const char *line)
{
	u64 len = 0;

	while (line[len])
		len++;
	ks_record(line, len, &matched, 0);
}

static void expect(int cond, const char *what)
{
	printf("%-70s %s\n", what, cond ? "ok" : "FAIL");
	if (!cond)
		failures++;
}

static void reset_sym(void)
{
	memset(&the_sym, 0, sizeof(the_sym));
	undefs[0].resolved = 0;
	matched = 0;
}

int main(void)
{
	undefs[0].name = "__stack_chk_guard";
	undefs[0].len = (u32)strlen("__stack_chk_guard");
	undefs[0].sym = &the_sym;
	undefs[0].bind = 1;
	undefs[0].resolved = 0;
	nundef = 1;

	/* 1. A module record must never be adopted, however exactly the name matches. */
	reset_sym();
	feed("ffffffffdeadbeef d __stack_chk_guard [kernelsu]");
	expect(matched == 0 && !undefs[0].resolved && the_sym.st_shndx != SHN_ABS,
	       "module record with a matching name is not adopted");
	expect(ks_module == 1, "the skipped module record is counted as such");

	/* 2. The kernel's own record is adopted. */
	feed("ffff800080123456 D __stack_chk_guard");
	expect(matched == 1 && undefs[0].resolved && the_sym.st_shndx == SHN_ABS,
	       "kernel record with the same name is adopted");
	expect(the_sym.st_value == 0xffff800080123456ULL,
	       "the address written is the kernel's");

	/* 3. kallsyms prints module symbols AFTER the kernel's, and the matcher is
	 *    last-occurrence-wins - so before this rule a module record would have
	 *    overwritten the kernel address.  This is the regression case. */
	feed("ffffffffdeadbeef d __stack_chk_guard [kernelsu]");
	expect(the_sym.st_value == 0xffff800080123456ULL,
	       "a later module record does not overwrite the kernel address");

	/* 4. A module record whose name is the only occurrence resolves nothing at all:
	 *    the entry must stay SHN_UNDEF so the kernel refuses the load out loud
	 *    ("Unknown symbol ...") instead of jumping into another module. */
	reset_sym();
	feed("ffffffffdeadbeef d __stack_chk_guard [kernelsu]");
	expect(!undefs[0].resolved && the_sym.st_shndx == SHN_UNDEF,
	       "a name that only exists in a module stays unresolved");

	/* 5. The rules that were already there, so this file also pins them down.  The
	 *    counters accumulate across the whole run, so each one is compared against its
	 *    own value from just before the line in question. */
	{
		u64 before;

		reset_sym();
		before = ks_dotted;
		feed("ffff800080123456 d __stack_chk_guard.cold");
		expect(matched == 0 && ks_dotted == before + 1, "a dotted name is skipped");

		reset_sym();
		before = ks_abs_type;
		feed("ffff800080123456 A __stack_chk_guard");
		expect(matched == 0 && ks_abs_type == before + 1,
		       "an absolute (a/A) record is skipped, a zero-address one is not this case");

		reset_sym();
		before = ks_zero;
		feed("0000000000000000 D __stack_chk_guard");
		expect(matched == 0 && ks_zero == before + 1, "a zero address is skipped");
	}

	reset_sym();
	feed("ffff800080123456 D __stack_chk_guard");
	expect(matched == 1, "an ordinary kernel record still matches");

	/* 6. A record for another name is not confused with ours. */
	reset_sym();
	feed("ffff800080123456 D __stack_chk_fail");
	expect(matched == 0, "a different kernel name does not match");

	printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "all match rules ok",
	       failures, failures == 1 ? "" : "s");
	return failures ? 1 : 0;
}
