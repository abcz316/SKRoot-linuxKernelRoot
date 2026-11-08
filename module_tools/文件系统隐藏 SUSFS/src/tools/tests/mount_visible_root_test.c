// SPDX-License-Identifier: GPL-2.0-only
/* Reuse typed VFS doubles without executing the completed baseline suite. */
#define main mount_runtime_previous_main
#include "mount_runtime_test.c"
#undef main

static unsigned int scenarios;

static void visible_base(unsigned int count)
{
	base(count);
	scenarios++;
	/* root row 10243 has an invisible parent 10242, not a self-parent. */
	mounts[0].mnt_id = 10243;
	mounts[0].mnt_parent = &mounts[1];
	mounts[1].mnt_id = 10242;
	mounts[1].mnt_parent = &mounts[1];
	mounts[1].mnt_ns = &other_ns;
	mounts[2].mnt_parent = &mounts[3];
	mounts[3].mnt_parent = &mounts[0];
}

static void visible_success(void)
{
	const struct skp_group_mount_object *object;
	expect(!skp_group_mounts_runtime_prepare(&config, &runtime),
	       "complete Android root overmount is supported");
	object = skp_group_mounts_objects(runtime);
	expect(object[0].chain_count == 3 && refs == 3 && paths == 1 &&
	       ns.references == 1 && !other_ns.references, "only exact visible chain is pinned");
	expect(object[0].cookies[0] == (u64)(unsigned long)&mounts[2].mnt &&
	       object[0].cookies[1] == (u64)(unsigned long)&mounts[3].mnt &&
	       object[0].cookies[2] == (u64)(unsigned long)&mounts[0].mnt &&
	       object[0].ids[2] == 10243 && !mounts[1].mnt.references,
	       "last retained mount is publisher root, invisible parent never captured");
	expect(skp_group_mounts_runtime_stable(runtime), "overmount snapshot stable");
}

int main(void)
{
	unsigned int i;
	struct skp_group_mount_object *object;
	visible_base(1); visible_success();
	mounts[1].mnt_id++; mounts[1].mnt_ns = NULL;
	expect(skp_group_mounts_runtime_stable(runtime), "outside-view ancestor changes do not widen capture");
	release();
	visible_base(1); memset(config.mounts[0].path, 0, sizeof(config.mounts[0].path));
	strcpy(config.mounts[0].path, "/root"); failure(-EINVAL);
	expect(lookups == 1, "root rejection reached actual mount capture, not path-tail validation");
	visible_base(1); fs.root.dentry = &subdir; failure(-EOPNOTSUPP);
	visible_base(1); mounts[0].mnt_ns = &other_ns; failure(-EOPNOTSUPP);
	visible_base(1); mounts[3].mnt_parent = &mounts[1]; failure(-ESTALE);
	visible_base(1); mounts[3].mnt_parent = &mounts[3]; failure(-ESTALE);
	visible_base(1); mounts[3].mnt_parent = NULL; failure(-ESTALE);
	visible_base(1); mounts[3].mnt_parent = &mounts[4];
	mounts[4].mnt_parent = &mounts[4]; failure(-ESTALE);
	visible_base(1); mounts[3].mnt_parent = &mounts[2]; failure(-E2BIG);
	visible_base(2); fail_lookup = 2; failure(-ENOENT);
	visible_base(1); change_mount_root_on_lookup = true; failure(-ESTALE);
	visible_base(1); visible_success();
	object = (struct skp_group_mount_object *)skp_group_mounts_objects(runtime);
	object[0].chain_count = 2;
	expect(!skp_group_mounts_runtime_stable(runtime), "truncated chain must still end at exact publisher root");
	object[0].chain_count = 3;
	for (i = 0; i <= 3; ++i) {
		if (i == 1) continue; /* deliberately invisible */
		mounts[i].mnt_ns = &other_ns;
		expect(!skp_group_mounts_runtime_stable(runtime), "any held mount namespace change invalidates");
		mounts[i].mnt_ns = &ns;
		mounts[i].mnt_id++;
		expect(!skp_group_mounts_runtime_stable(runtime), "any held mount ID change invalidates");
		mounts[i].mnt_id--;
	}
	mounts[2].mnt_parent = &mounts[0];
	expect(!skp_group_mounts_runtime_stable(runtime), "selected mount reparent invalidates");
	mounts[2].mnt_parent = &mounts[3];
	mounts[3].mnt_parent = &mounts[1];
	expect(!skp_group_mounts_runtime_stable(runtime), "intermediate escaping parent invalidates");
	mounts[3].mnt_parent = &mounts[0];
	mounts[0].mnt.mnt_root = &subdir;
	expect(!skp_group_mounts_runtime_stable(runtime), "publisher must remain a complete mount root");
	mounts[0].mnt.mnt_root = &dentries[0];
	proxy.mnt_ns = &other_ns;
	expect(!skp_group_mounts_runtime_stable(runtime), "foreign reader namespace remains native");
	proxy.mnt_ns = &ns;
	fs.root.dentry = &subdir;
	expect(!skp_group_mounts_runtime_stable(runtime), "reader subdirectory chroot remains native");
	fs.root.dentry = &dentries[0]; fs.root.mnt = &mounts[3].mnt;
	expect(!skp_group_mounts_runtime_stable(runtime), "different complete reader root remains native");
	fs.root.mnt = &mounts[0].mnt;
	topology.seqcount.seqcount.sequence = 1; topology.locked = true;
	sequence_reads = sequence_retries = 0;
	expect(!skp_group_mounts_runtime_stable(runtime) && sequence_reads == 2 && sequence_retries == 1,
	       "odd topology writer returns without waiting");
	topology.seqcount.seqcount.sequence = 2; topology.locked = false;
	fs.seq.seqcount.sequence = 1; sequence_reads = sequence_retries = 0;
	expect(!skp_group_mounts_runtime_stable(runtime) && sequence_reads == 1 && !sequence_retries,
	       "odd fs writer returns without waiting");
	fs.seq.seqcount.sequence = 2; change_root_during_topology = true;
	expect(!skp_group_mounts_runtime_stable(runtime), "fs counter is rechecked after topology validation");
	change_topology_on_retry = true;
	expect(!skp_group_mounts_runtime_stable(runtime), "topology counter is rechecked after validation");
	expect(skp_group_mounts_runtime_stable(runtime), "restored exact visible view stable");
	release();
	base(0);
	expect(!subdir.references && !paths && !refs, "all success/failure mount/dentry refs released");
	printf("MOUNT_VISIBLE_ROOT_HOST checks=%u scenarios=%u passed=true kernel_calls=false production_source=true\n",
	       checks, scenarios);
	return 0;
}
