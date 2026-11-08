// SPDX-License-Identifier: GPL-2.0-only
/* Production full runtime with typed dependency doubles. Each underlying VFS
 * resolver has its own production-source regression; no kernel execution. */
#include "../../kernel/skp_full_objects_runtime.h"
#include "../../kernel/skp_mount_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct skp_group_mounts_runtime { struct skp_group_mount_object objects[SKP_GROUP_MOUNTS_MAX]; bool stable; };
static struct mount mounts[2 * SKP_GROUP_REDIRECTS_MAX];
static unsigned int checks, allocs, live, refs, calls, fail_alloc, fail_redirect;
static unsigned int fail_objects, fail_mounts, alias_redirect;
static struct skp_full_objects_runtime *output;
static void expect(int condition, const char *message)
{
	++checks;
	if (!condition) { fprintf(stderr, "FAIL check=%u %s\n", checks, message); exit(1); }
}
void *kvzalloc(size_t size, unsigned int flags)
{
	void *memory;
	expect(flags == GFP_KERNEL && !output, "candidate private process allocation");
	if (++allocs == fail_alloc) return NULL;
	memory = calloc(1, size); expect(memory != NULL, "host allocation"); ++live; return memory;
}
void kvfree(const void *p) { if (p) { expect(live > 0, "one owned allocation freed"); --live; free((void *)p); } }
void mntput(struct vfsmount *mnt) { expect(mnt && mnt->references && refs, "held mount ref released"); --mnt->references; --refs; }
int skp_group_objects_runtime_prepare(const struct skp_group_objects_config *config,
		struct skp_group_objects_runtime **runtime)
{
	expect(!output, "objects prepare sees no published full candidate");
	if (fail_objects) return -ENOENT;
	*runtime = kvzalloc(sizeof(**runtime), GFP_KERNEL);
	if (!*runtime) return -ENOMEM;
	(*runtime)->config = *config; return 0;
}
void skp_group_objects_runtime_free(struct skp_group_objects_runtime *runtime) { kvfree(runtime); }
int susfs_open_redirect_resolve_group(const char *source, const char *target,
		struct skp_group_redirect_object *object, struct kstatfs *statfs,
		struct vfsmount **source_mnt, struct vfsmount **target_mnt)
{
	unsigned int i = calls++;
	expect(!output && source[0] == '/' && target[0] == '/', "redirect detached inputs");
	if (calls == fail_redirect) return -ENOENT;
	memset(object, 0, sizeof(*object));
	object->source.dev = object->target.dev = 123;
	object->source.ino = alias_redirect ? 1 : i * 2 + 1;
	object->target.ino = i * 2 + 2;
	object->source_mnt_id = mounts[i * 2].mnt_id;
	object->target_mnt_id = mounts[i * 2 + 1].mnt_id;
	*source_mnt = &mounts[i * 2].mnt;
	*target_mnt = &mounts[i * 2 + 1].mnt;
	++(*source_mnt)->references; ++(*target_mnt)->references; refs += 2;
	statfs->f_type = i + 100; return 0;
}
int skp_group_mounts_runtime_prepare(const struct skp_full_objects_config *config,
		struct skp_group_mounts_runtime **runtime)
{
	expect(!output && config, "mount prepare still private");
	if (fail_mounts) return -ENOENT;
	*runtime = kvzalloc(sizeof(**runtime), GFP_KERNEL);
	if (!*runtime) return -ENOMEM;
	(*runtime)->stable = true; return 0;
}
void skp_group_mounts_runtime_free(struct skp_group_mounts_runtime *runtime) { kvfree(runtime); }
bool skp_group_mounts_runtime_stable(const struct skp_group_mounts_runtime *runtime) { return runtime && runtime->stable; }
const struct skp_group_mount_object *skp_group_mounts_objects(const struct skp_group_mounts_runtime *runtime) { return runtime ? runtime->objects : NULL; }
static struct skp_full_objects_config config;
static void reset(void)
{
	unsigned int i;
	expect(!output && !refs && !live, "all previous references and allocations drained");
	allocs = calls = fail_alloc = fail_redirect = fail_objects = fail_mounts = alias_redirect = 0;
	for (i = 0; i < 2 * SKP_GROUP_REDIRECTS_MAX; ++i) {
		expect(!mounts[i].mnt.references, "no mount leaks"); mounts[i].mnt_id = i + 1;
	}
}
static void release(void) { struct skp_full_objects_runtime *r = output; output = NULL; skp_full_objects_runtime_free(r); }
int main(void)
{
	unsigned int i;
	struct skp_redirect_prepare_refs *temporary;
	config.objects.paths.subjects.version = 1;
	config.objects.paths.subjects.facts_generation = 1;
	config.objects.paths.subjects.profile_count = 1;
	config.objects.paths.version = config.objects.version = config.version = 1;
	reset();
	expect(!skp_full_objects_runtime_prepare(&config, &output), "empty complete snapshot prepares");
	expect(skp_full_objects_runtime_stable(output), "empty snapshot stable"); release();
	config.redirect_count = SKP_GROUP_REDIRECTS_MAX;
	config.objects.paths.subjects.profile_count = 2;
	config.objects.paths.subjects.profiles[1] = 7;
	for (i = 0; i < SKP_GROUP_REDIRECTS_MAX; ++i) {
		config.redirects[i].profile_id = 7;
		snprintf(config.redirects[i].source, sizeof(config.redirects[i].source), "/source/%u", i);
		snprintf(config.redirects[i].target, sizeof(config.redirects[i].target), "/target/%u", i);
	}
	reset(); expect(!skp_full_objects_runtime_prepare(&config, &output), "maximum redirects prepare");
	expect(refs == 128 && skp_full_objects_runtime_stable(output), "all temporary IDs held through publication boundary");
	expect(output->source_statfs[63].f_type == 163, "all detached metadata copied");
	expect(output->redirects[63].profile_id == 7, "resolver output cannot erase configured profile");
	mounts[7].mnt_id++; expect(!skp_full_objects_runtime_stable(output), "legacy renumber during prepare invalidates candidate"); --mounts[7].mnt_id;
	output->mounts->stable = false; expect(!skp_full_objects_runtime_stable(output), "mount topology invalidates candidate"); output->mounts->stable = true;
	temporary = output->temporary; output->temporary = NULL;
	expect(!skp_full_objects_runtime_stable(output), "prepare-only guard not reused after detach");
	release(); expect(refs == 128 && !output, "retirement cannot steal detached preparation refs");
	skp_redirect_prepare_refs_free(temporary); expect(!refs && !live, "detached refs released once outside transaction");
	for (i = 1; i <= SKP_GROUP_REDIRECTS_MAX; ++i) {
		reset(); fail_redirect = i;
		expect(skp_full_objects_runtime_prepare(&config, &output) == -ENOENT && !output, "every redirect failure rejects whole snapshot");
		expect(!refs && !live, "every prefix fully unwound");
	}
	for (i = 1; i <= 4; ++i) {
		reset(); fail_alloc = i;
		expect(skp_full_objects_runtime_prepare(&config, &output) == -ENOMEM && !output && !refs && !live,
		       "each dependency allocation failure unwinds refs");
	}
	reset(); fail_objects = 1;
	expect(skp_full_objects_runtime_prepare(&config, &output) == -ENOENT && !output && !refs && !live && !calls,
	       "earlier object failure does no redirect work");
	reset(); fail_mounts = 1;
	expect(skp_full_objects_runtime_prepare(&config, &output) == -ENOENT && !output && !refs && !live, "mount failure releases every redirect prefix");
	reset(); alias_redirect = 1;
	expect(skp_full_objects_runtime_prepare(&config, &output) == -EEXIST && !output && !refs && !live,
	       "resolved alias preserves old snapshot, frees all refs");
	reset(); config.reserved = 1;
	expect(skp_full_objects_runtime_prepare(&config, &output) == -EINVAL && !allocs && !calls, "invalid input rejected before preparation");
	expect(skp_full_objects_runtime_prepare(NULL, NULL) == -EINVAL, "null output rejected");
	skp_full_objects_runtime_free(NULL); skp_redirect_prepare_refs_free(NULL);
	printf("FULL_OBJECTS_RUNTIME_HOST checks=%u passed=true kernel_calls=false production_source=true\n", checks); return 0;
}
