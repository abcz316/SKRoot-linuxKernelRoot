// SPDX-License-Identifier: GPL-2.0-only
/* Appended to production adapter functions by the regression runner. */
static struct skp_full_objects_message full_message;
static struct skp_group_objects_message object_message;
static struct skp_group_paths_message path_message;
static struct skp_policy_message subject_message;
_Alignas(struct skp_scoped_managed_policy_message)
static unsigned char invalid_frame[sizeof(struct skp_scoped_managed_policy_message)];
static struct skp_subject_policy *test_subjects;
static void valid_subjects(struct skp_subject_policy *p)
{
	memset(p, 0, sizeof(*p)); p->version = 1; p->profile_count = 1; p->facts_generation = 1;
}
static void frame(void *data, size_t size, unsigned int command)
{
	struct skp_policy_message *p = data;
	p->magic = SKP_POLICY_MESSAGE_MAGIC; p->version = 1;
	p->size = (u32)size; p->command = command; p->expected_generation = policy_generation;
}
static ssize_t write_object(void)
{
	current_test_uid = 0;
	return skp_policy_write(NULL, (const char *)&object_message, sizeof(object_message), NULL);
}
static void status_case(const char *label)
{
	struct seq_file stream = {0};
	unsigned int uid = current_test_uid;
	current_test_uid = 10001;
	expect(skp_policy_show(&stream, NULL) == -EACCES && !stream.length,
	       "status rechecks actual root credentials");
	current_test_uid = 0;
	expect(!skp_policy_show(&stream, NULL) && stream.length && !locks,
	       "production status rendered under writer guard");
	printf("POLICY_STATUS_CASE %s %s", label, stream.text);
	current_test_uid = uid;
}
static void reject_frame(const void *data, size_t size, ssize_t error)
{
	struct skp_policy_snapshot *before = active_policy;
	u64 generation = policy_generation;
	unsigned int old_prepares = prepares, old_publications = publications;
	unsigned int old_pins = pins, old_arms = arm_paths + arm_kstats + arm_maps + arm_redirects + arm_mounts;
	current_test_uid = 0;
	expect(skp_policy_write(NULL, data, size, NULL) == error, "malformed frame rejected");
	expect(before == active_policy && generation == policy_generation &&
	       old_prepares == prepares && old_publications == publications && old_pins == pins &&
	       old_arms == arm_paths + arm_kstats + arm_maps + arm_redirects + arm_mounts && !locks && !rcu_depth,
	       "malformed frame leaves state untouched before filesystem preparation");
}
static void malformed_frames(void)
{
	struct skp_policy_message *header = (void *)invalid_frame;
	struct skp_group_objects_message *objects = (void *)invalid_frame;
	struct skp_group_paths_message *paths = (void *)invalid_frame;
	unsigned int commands[] = { SKP_POLICY_REPLACE, SKP_POLICY_USE_UPSTREAM,
		SKP_POLICY_REPLACE_PATHS, SKP_POLICY_REPLACE_OBJECTS, SKP_POLICY_REPLACE_FULL, SKP_POLICY_REPLACE_MANAGED, SKP_POLICY_REPLACE_SCOPED_MANAGED, 0, 99 };
	size_t sizes[] = { sizeof(struct skp_policy_message), sizeof(struct skp_group_paths_message),
		sizeof(struct skp_group_objects_message), sizeof(struct skp_full_objects_message), sizeof(struct skp_managed_policy_message), sizeof(struct skp_scoped_managed_policy_message) };
	unsigned int i, j;
	for (i = 0; i < 4; ++i) {
		memcpy(invalid_frame, &object_message, sizeof(object_message));
		if (i == 0) header->magic ^= 1;
		if (i == 1) header->version++;
		if (i == 2) header->size--;
		if (i == 3) header->reserved = 1;
		reject_frame(invalid_frame, sizeof(object_message), -EINVAL);
	}
	for (i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i)
		for (j = 0; j < sizeof(sizes) / sizeof(sizes[0]); ++j) {
			unsigned int command = commands[i];
			if ((command == SKP_POLICY_REPLACE || command == SKP_POLICY_USE_UPSTREAM) && j == 0)
				continue;
			if (command == SKP_POLICY_REPLACE_PATHS && j == 1) continue;
			if (command == SKP_POLICY_REPLACE_OBJECTS && j == 2) continue;
			if (command == SKP_POLICY_REPLACE_FULL && j == 3) continue;
			if (command == SKP_POLICY_REPLACE_MANAGED && j == 4) continue;
			if (command == SKP_POLICY_REPLACE_SCOPED_MANAGED && j == 5) continue;
			memset(invalid_frame, 0, sizeof(invalid_frame));
			frame(invalid_frame, sizes[j], command);
			reject_frame(invalid_frame, sizes[j], command == 0 || command == 99 ? -EINVAL : -EMSGSIZE);
		}
	for (i = 0; i < 6; ++i) {
		memcpy(invalid_frame, &object_message, sizeof(object_message));
		if (i == 0) objects->config.version = 0;
		if (i == 1) objects->config.kstat_count = SKP_GROUP_KSTATS_MAX + 1;
		if (i == 2) objects->config.map_count = SKP_GROUP_MAPS_MAX + 1;
		if (i == 3) objects->config.kstats[0].values.flags = 0;
		if (i == 4) objects->config.kstats[0].values.size = -1;
		if (i == 5) objects->config.maps[SKP_GROUP_MAPS_MAX - 1].path[0] = 'x';
		reject_frame(invalid_frame, sizeof(object_message), -EINVAL);
	}
	memset(invalid_frame, 0, sizeof(invalid_frame));
	frame(invalid_frame, sizeof(*paths), SKP_POLICY_REPLACE_PATHS);
	valid_subjects(&paths->config.subjects);
	paths->config.version = 1;
	paths->config.rules[SKP_GROUP_PATHS_MAX - 1].path[0] = 'x';
	reject_frame(invalid_frame, sizeof(*paths), -EINVAL);
	memset(invalid_frame, 0, sizeof(invalid_frame));
	frame(invalid_frame, sizeof(*header), SKP_POLICY_REPLACE);
	valid_subjects(&header->policy);
	header->policy.reserved[0] = 1;
	reject_frame(invalid_frame, sizeof(*header), -EINVAL);
	header->command = SKP_POLICY_USE_UPSTREAM;
	reject_frame(invalid_frame, sizeof(*header), -EINVAL);
	reject_frame(invalid_frame, sizeof(*header) - 1, -EMSGSIZE);
	reject_frame(invalid_frame, sizeof(invalid_frame) + 1, -EMSGSIZE);
}
static struct skp_managed_policy_message managed_message, bad_managed;
static void managed_frame(void)
{
	frame(&managed_message, sizeof(managed_message), SKP_POLICY_REPLACE_MANAGED);
	managed_message.body.facts_deadline_ns = fake_boottime_ns + 20000000000ULL;
}
static void managed_status(const char *label, bool valid, bool owner, bool enabled)
{
	struct seq_file stream = {0};
	unsigned int uid = current_test_uid;
	current_test_uid = 0;
	expect(!skp_policy_show(&stream, NULL) && stream.length < 4096, "managed production status fits");
	expect(strstr(stream.text, "\"managed\":true") &&
	       strstr(stream.text, "\"managed_message_bytes\":121712") &&
	       strstr(stream.text, valid ? "\"facts_valid\":true" : "\"facts_valid\":false") &&
	       strstr(stream.text, owner ? "\"managed_owner_alive\":true" : "\"managed_owner_alive\":false") &&
	       strstr(stream.text, owner ? "\"managed_owner_is_current\":true" : "\"managed_owner_is_current\":false") &&
	       strstr(stream.text, enabled ? "\"object_rules_enabled\":true" : "\"object_rules_enabled\":false"),
	       "managed status reports actual lease and flags");
	printf("POLICY_MANAGED_CASE %s %s", label, stream.text);
	current_test_uid = uid;
}
static void managed_queries(bool enabled)
{
	struct skp_kstat_query_result k;
	struct skp_map_query_result m;
	struct skp_redirect_query_result r;
	struct skp_mount_query_result mt;
	struct skp_fdinfo_query_result fd;
	struct super_block sb = {.s_dev = 123};
	struct inode inode = {.i_sb = &sb, .i_ino = 456};
	bool hidden;
	current = &app_task; current_test_uid = 10001;
	expect(skp_policy_paths_inode_override(&inode, &hidden) && hidden == enabled,
	       "managed path lease is authoritative in same snapshot");
	expect(skp_policy_paths_dirent_override(456, "fixture", &hidden) && hidden == enabled,
	       "managed dirent shares facts lease");
	expect(skp_policy_kstat_query(123,456,&k) == SKP_OBJECT_GROUPED && k.matched == enabled,
	       "managed kstat uses lease without global fallback");
	expect(skp_policy_kstat_maps_query(123,456,0,&k) == SKP_OBJECT_GROUPED && k.matched == enabled,
	       "managed maps kstat shares lease");
	expect(skp_policy_map_query(123,456,&m) == SKP_OBJECT_GROUPED && m.hidden == enabled,
	       "managed map lease authority");
	expect(skp_policy_redirect_query(123,789,3,31,SKP_REDIRECT_FORWARD,&r) == SKP_OBJECT_GROUPED && r.matched == enabled,
	       "managed forward redirect lease authority");
	expect(skp_policy_redirect_query(123,790,4,32,SKP_REDIRECT_REVERSE,&r) == SKP_OBJECT_GROUPED && r.matched == enabled,
	       "managed reverse redirect lease authority");
	expect(skp_policy_mount_query(1031,31,1,&mt) == SKP_OBJECT_GROUPED && mt.hidden == enabled,
	       "managed mount lease authority");
	expect(skp_policy_fdinfo_query(790,32,&fd) == SKP_OBJECT_GROUPED && fd.rewrite_ino == enabled &&
	       fd.ino == (enabled ? 789U : 790U) && fd.mnt_id == (enabled ? 1U : 32U),
	       "managed combined fdinfo lease authority");
}
static void managed_bootstrap_tests(struct file *file)
{
	static struct skp_managed_policy_message saved;
	unsigned int i;
	saved = managed_message;
	for (i=0;i<9;++i) {
		struct skp_subject_policy *subjects;
		struct skp_group_paths_config *paths;
		unsigned int old_publications=publications, old_arms=arm_paths+arm_kstats+arm_maps+arm_redirects+arm_mounts;
		bool blocked = i==0 || i==4 || i==5;
		managed_message = saved;
		managed_message.body.flags = SKP_MANAGED_OBJECT_RULES_ENABLED;
		paths=&managed_message.body.config.objects.paths; subjects=&paths->subjects;
		valid_subjects(subjects); paths->path_count=1;
		strcpy(paths->rules[0].path,"/fixture/proc-alias");
		if(i==1) subjects->flags=SKP_SUBJECT_EXEMPT_ROOT;
		if(i==2) { subjects->mode=SKP_SUBJECT_BLACKLIST; subjects->blacklist_count=1; subjects->blacklist[0]=10001; }
		if(i==3 || i==4) {
			subjects->profile_count=2; subjects->profiles[1]=7;
			subjects->binding_count=1; subjects->bindings[0].uid=0; subjects->bindings[0].profile_id=7;
			if(i==4) paths->rules[0].profile_id=7;
		}
		if(i==5) { subjects->mode=SKP_SUBJECT_BLACKLIST; subjects->blacklist_count=1; subjects->blacklist[0]=0; }
		if(i==6) strcpy(paths->rules[0].path,"/fixture/proc-child");
		if(i==7) strcpy(paths->rules[0].path,"/fixture/other-root");
		if(i==8) proc_root.i_mode=0100000;
		managed_frame(); current=&owner_a; current_test_uid=0;
		expect(skp_policy_write(file,(const char *)&managed_message,sizeof(managed_message),NULL)==
		       (blocked ? -EBUSY : (ssize_t)sizeof(managed_message)),
		       "managed root bootstrap checks selected profile and resolved proc root aliases");
		if(blocked) {
			expect(!active_policy && publications==old_publications &&
			       old_arms==arm_paths+arm_kstats+arm_maps+arm_redirects+arm_mounts && owner_a.refs==1,
			       "unsafe proc root rejected before arming or publication and refs released");
		} else {
			memset(&subject_message.policy,0,sizeof(subject_message.policy));
			frame(&subject_message,sizeof(subject_message),SKP_POLICY_USE_UPSTREAM);
			expect(skp_policy_write(NULL,(const char *)&subject_message,sizeof(subject_message),NULL)==sizeof(subject_message) &&
			       !active_policy && owner_a.refs==1, "safe or root-exempt candidate can be explicitly reset");
		}
		proc_root.i_mode=0040000;
	}
	managed_message=saved;
	/* The same held object remains legal for the original raw developer ABI. */
	full_message.config=managed_message.body.config;
	full_message.config.objects.paths.path_count=1;
	strcpy(full_message.config.objects.paths.rules[0].path,"/fixture/proc-alias");
	frame(&full_message,sizeof(full_message),SKP_POLICY_REPLACE_FULL);
	expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL)==sizeof(full_message),
	       "raw full protocol does not acquire managed bootstrap restrictions");
	memset(&subject_message.policy,0,sizeof(subject_message.policy));
	frame(&subject_message,sizeof(subject_message),SKP_POLICY_USE_UPSTREAM);
	expect(skp_policy_write(NULL,(const char *)&subject_message,sizeof(subject_message),NULL)==sizeof(subject_message),
	       "raw alias test explicitly returns upstream");
}
static void managed_tests(void)
{
	struct file fd_a = {0}, fd_b = {0}, fd_child = {0};
	struct skp_policy_snapshot *before;
	u64 generation;
	unsigned int i, prepare_count;
	owner_a.group_leader = &owner_a; owner_a.alive = true;
	owner_b.group_leader = &owner_b; owner_b.alive = true;
	child_task.group_leader = &child_task; child_task.alive = true;
	app_task.group_leader = &app_task; app_task.alive = true;
	current = &owner_a; current_test_uid = 10001;
	expect(skp_policy_open(NULL,&fd_a) == -EACCES && !fd_a.private_data, "lease open requires actual root");
	current_test_uid = 0;
	expect(!skp_policy_open(NULL,&fd_a) && owner_a.refs == 1, "actual opener leader reference acquired");
	current = &owner_b;
	expect(!skp_policy_open(NULL,&fd_b) && owner_b.refs == 1, "independent exact session");
	current = &owner_a;
	memset(&managed_message,0,sizeof(managed_message));
	managed_message.body.version = 1; managed_message.body.flags = SKP_MANAGED_OBJECT_RULES_ENABLED;
	managed_message.body.config_revision = 17;
	memset(managed_message.body.request_id,0x12,sizeof(managed_message.body.request_id));
	memset(managed_message.body.config_digest,0x34,sizeof(managed_message.body.config_digest));
	memset(managed_message.body.inventory_digest,0x56,sizeof(managed_message.body.inventory_digest));
	valid_subjects(&managed_message.body.config.objects.paths.subjects);
	managed_message.body.config.version = managed_message.body.config.objects.version =
		managed_message.body.config.objects.paths.version = 1;
	managed_message.body.config.objects.paths.path_count = 1;
	strcpy(managed_message.body.config.objects.paths.rules[0].path,"/fixture/hidden");
	managed_message.body.config.objects.kstat_count = managed_message.body.config.objects.map_count = 1;
	strcpy(managed_message.body.config.objects.kstats[0].path,"/fixture/a");
	managed_message.body.config.objects.kstats[0].values.flags = 1;
	managed_message.body.config.objects.kstats[0].values.ino = 8001;
	strcpy(managed_message.body.config.objects.maps[0].path,"/fixture/a");
	managed_message.body.config.redirect_count = 1; managed_message.body.config.mount_count = 2;
	strcpy(managed_message.body.config.redirects[0].source,"/fixture/source");
	strcpy(managed_message.body.config.redirects[0].target,"/fixture/target");
	strcpy(managed_message.body.config.mounts[0].path,"/fixture/mount-source");
	strcpy(managed_message.body.config.mounts[1].path,"/fixture/mount-target");
	managed_frame();
	for (i=0;i<10;++i) {
		bad_managed = managed_message;
		if (i==0) bad_managed.body.version++;
		if (i==1) bad_managed.body.flags = 2;
		if (i==2) bad_managed.body.config_revision = 0;
		if (i==3) memset(bad_managed.body.request_id,0,16);
		if (i==4) memset(bad_managed.body.config_digest,0,32);
		if (i==5) memset(bad_managed.body.inventory_digest,0,32);
		if (i==6) bad_managed.body.facts_deadline_ns = fake_boottime_ns;
		if (i==7) bad_managed.body.facts_deadline_ns = fake_boottime_ns + SKP_MANAGED_FACTS_LEASE_MAX_NS + 1;
		if (i==8) bad_managed.body.flags = 0;
		if (i==9) bad_managed.body.config.reserved = 1;
		before=active_policy; generation=policy_generation; prepare_count=prepares;
		expect(skp_policy_write(&fd_a,(const char *)&bad_managed,sizeof(bad_managed),NULL)==-EINVAL &&
		       active_policy==before && policy_generation==generation && prepares==prepare_count && owner_a.refs==1,
		       "invalid managed metadata never resolves publishes or leaks owner ref");
	}
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message)-1,NULL)==-EMSGSIZE,
	       "truncated managed metadata frame rejected");
	current=&child_task;
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==-EACCES,
	       "inherited or passed descriptor cannot publish as opener");
	current=&owner_a; managed_message.expected_generation--;
	prepare_count=prepares;
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==-ESTALE && prepares==prepare_count && owner_a.refs==1,
	       "managed stale precheck avoids resolution and releases candidate task ref");
	managed_frame(); race_prepare=1; before=active_policy;
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==-ESTALE && active_policy==before && owner_a.refs==1,
	       "managed second CAS leaves receipt and rules together");
	managed_frame(); advance_during_prepare=20000000000ULL;
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==-ESTALE && active_policy==before && owner_a.refs==1,
	       "lease expiring during VFS preparation cannot publish");
	managed_frame(); kill_during_prepare=&owner_a;
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==-EACCES && active_policy==before && owner_a.refs==1,
	       "owner death during VFS preparation cannot publish");
	owner_a.exit_state=0; managed_frame(); advance_during_arm=20000000000ULL;
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==-ESTALE && active_policy==before && owner_a.refs==1,
	       "lease expiring during sleeping hook arming cannot publish receipt");
	managed_frame();
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==sizeof(managed_message) &&
	       active_policy->managed.config_revision==17 && owner_a.refs==2 &&
	       !memcmp(&active_policy->managed,&managed_message.body,sizeof(active_policy->managed)),
	       "receipt and five object families atomically publish");
	managed_status("live",true,true,true);
	{
		char output[4096] = {0}; loff_t position = 0;
		current_test_uid=10001;
		expect(skp_policy_read(&fd_a,output,sizeof(output)-1,&position)==-EACCES && !position, "actual proc read rechecks root");
		current_test_uid=0;
		expect(skp_policy_read(&fd_a,output,sizeof(output)-1,&position)>0 &&
		       strstr(output,"\"managed_owner_is_current\":true"), "actual owner proc read includes atomic managed receipt");
		current=&owner_b; position=0; memset(output,0,sizeof(output));
		expect(skp_policy_read(&fd_b,output,sizeof(output)-1,&position)>0 &&
		       strstr(output,"\"managed_owner_alive\":true") &&
		       strstr(output,"\"managed_owner_is_current\":false"), "other reader preflights known busy without a write");
		current=&owner_a;
	}
	managed_queries(true);
	before=active_policy; current=&owner_b; current_test_uid=0; managed_frame();
	prepare_count=prepares;
	expect(skp_policy_write(&fd_b,(const char *)&managed_message,sizeof(managed_message),NULL)==-EBUSY &&
	       active_policy==before && prepares==prepare_count && owner_b.refs==1, "other live manager cannot replace owner");
	current=&owner_a; managed_frame(); managed_message.body.config_revision++;
	memset(managed_message.body.request_id,0x67,16); fail_prepare=1;
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==-ENOENT &&
	       active_policy==before && active_policy->managed.config_revision==17 && active_policy->managed.request_id[0]==0x12,
	       "failed candidate cannot partially change published receipt");
	fail_prepare=0; fake_boottime_ns=active_policy->managed.facts_deadline_ns;
	managed_status("expired",false,true,true); managed_queries(false);
	current=&owner_b; current_test_uid=0; managed_frame();
	expect(skp_policy_write(&fd_b,(const char *)&managed_message,sizeof(managed_message),NULL)==-EBUSY,
	       "expired facts do not hand ownership to another live process");
	frame(&full_message,sizeof(full_message),SKP_POLICY_REPLACE_FULL);
	expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL)==-EOPNOTSUPP,
	       "managed expiry retains raw full format barrier");
	current=&owner_a;
	expect(!skp_policy_release(NULL,&fd_a) && owner_a.refs==1, "descriptor close keeps only snapshot task ref");
	managed_status("closed",false,false,true); managed_queries(false);
	current=&owner_a; current_test_uid=0;
	expect(!skp_policy_open(NULL,&fd_a), "same task can open a fresh session");
	managed_queries(false);
	current=&owner_b; current_test_uid=0; managed_frame();
	expect(skp_policy_write(&fd_b,(const char *)&managed_message,sizeof(managed_message),NULL)==sizeof(managed_message) && owner_a.refs==1 && owner_b.refs==2,
	       "closed original descriptor permits fresh owner publication and drains old ref");
	owner_b.alive=false; managed_status("dead",false,false,true); managed_queries(false);
	current=&owner_a; current_test_uid=0; managed_frame();
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==sizeof(managed_message) && owner_b.refs==1,
	       "dead owning task permits verified new exact owner");
	managed_message.body.flags=0;
	memset(&managed_message.body.config,0,sizeof(managed_message.body.config));
	valid_subjects(&managed_message.body.config.objects.paths.subjects);
	managed_message.body.config.version=managed_message.body.config.objects.version=managed_message.body.config.objects.paths.version=1;
	managed_frame();
	expect(skp_policy_write(&fd_a,(const char *)&managed_message,sizeof(managed_message),NULL)==sizeof(managed_message), "disabled complete empty snapshot publishes");
	managed_status("disabled",true,true,false); managed_queries(false);
	for (i=1;i<=5;++i) {
		const void *data; size_t size;
		if(i==2) continue;
		if(i==1){ valid_subjects(&subject_message.policy); frame(&subject_message,sizeof(subject_message),i); data=&subject_message; size=sizeof(subject_message); }
		else if(i==3){ frame(&path_message,sizeof(path_message),i); data=&path_message; size=sizeof(path_message); }
		else if(i==4){ frame(&object_message,sizeof(object_message),i); data=&object_message; size=sizeof(object_message); }
		else { frame(&full_message,sizeof(full_message),i); data=&full_message; size=sizeof(full_message); }
		current_test_uid=0; current=&owner_a;
		expect(skp_policy_write(NULL,data,size,NULL)==-EOPNOTSUPP, "disabled managed blocks every older raw writer");
	}
	memset(&subject_message.policy,0,sizeof(subject_message.policy)); frame(&subject_message,sizeof(subject_message),2);
	expect(skp_policy_write(NULL,(const char *)&subject_message,sizeof(subject_message),NULL)==sizeof(subject_message) && !active_policy && owner_a.refs==1,
	       "explicit upstream reset releases managed receipt ownership");
	managed_bootstrap_tests(&fd_a);
	expect(!skp_policy_release(NULL,&fd_a) && !skp_policy_release(NULL,&fd_b) &&
	       !owner_a.refs && !owner_b.refs && !manager_count, "all proc sessions and task references drain");
	/* Keep the child storage observable: no raw PID/UID substitution occurs. */
	expect(!fd_child.private_data && !child_task.refs, "inherited write never creates child management role");
}
_Static_assert(sizeof(struct skp_managed_policy_message)==121712,"cmd6 ABI unchanged");
_Static_assert(sizeof(struct skp_full_objects_message)==121608,"cmd5 ABI unchanged");
_Static_assert(sizeof(struct skp_scoped_managed_policy_message)==256896,"cmd7 ABI");
_Static_assert(offsetof(struct skp_scoped_managed_policy_message,body)==32,"cmd7 header unchanged");
_Static_assert(offsetof(struct skp_scoped_managed_policy_message,scopes)==121712,"cmd7 preserves entire cmd6 prefix");
static struct skp_scoped_managed_policy_message scoped_message, bad_scoped;
static void scoped_frame(void)
{
	frame(&scoped_message,sizeof(scoped_message),SKP_POLICY_REPLACE_SCOPED_MANAGED);
	scoped_message.body.facts_deadline_ns=fake_boottime_ns+20000000000ULL;
}
static void scoped_status(const char* label)
{
	struct seq_file stream={0};
	current=&owner_a;current_test_uid=0;
	expect(!skp_policy_show(&stream,NULL)&&stream.length<4096,"scoped production status remains bounded");
	printf("POLICY_SCOPED_CASE %s %s",label,stream.text);
}
static void scoped_query(unsigned uid,bool hidden,bool other_families)
{
	struct super_block sb={.s_dev=123};
	struct inode inode={.i_sb=&sb,.i_ino=456};
	struct skp_kstat_query_result k;
	struct skp_map_query_result m;
	struct skp_redirect_query_result r;
	struct skp_mount_query_result mount;
	struct skp_fdinfo_query_result fd;
	bool found=false;
	current=&app_task;current_test_uid=uid;
	expect(skp_policy_paths_inode_override(&inode,&found)&&found==hidden,"adapter applies custom path independently of canonical global/profile gate");
	expect(skp_policy_paths_dirent_override(456,"fixture",&found)&&found==hidden,"adapter dirent uses same scoped publication");
	expect(skp_policy_kstat_query(123,456,&k)==SKP_OBJECT_GROUPED&&k.matched==other_families,"path overrides never alter canonical kstat gate");
	expect(skp_policy_map_query(123,456,&m)==SKP_OBJECT_GROUPED&&m.hidden==other_families,"path overrides never alter canonical map gate");
	expect(skp_policy_redirect_query(123,789,3,31,SKP_REDIRECT_FORWARD,&r)==SKP_OBJECT_GROUPED&&r.matched==other_families,"path overrides never alter canonical redirect gate");
	expect(skp_policy_mount_query(1031,31,1,&mount)==SKP_OBJECT_GROUPED&&mount.hidden==other_families,"path overrides never alter canonical mount gate");
	expect(skp_policy_fdinfo_query(790,32,&fd)==SKP_OBJECT_GROUPED&&fd.rewrite_ino==other_families,"combined fdinfo retains canonical facts");
}
static void scoped_tests(void)
{
	struct file fd={0},other_fd={0};
	struct skp_policy_snapshot *before;
	unsigned i,old_prepares,old_publications;
	u64 generation;
	owner_a.alive=true;owner_a.exit_state=0;owner_b.alive=true;owner_b.exit_state=0;
	current=&owner_a;current_test_uid=0;
	expect(!skp_policy_open(NULL,&fd),"scoped owner acquires its original exact proc session");
	memset(&scoped_message,0,sizeof(scoped_message));
	scoped_message.body.version=1;scoped_message.body.flags=SKP_MANAGED_OBJECT_RULES_ENABLED;
	scoped_message.body.config_revision=33;
	memset(scoped_message.body.request_id,0xab,16);memset(scoped_message.body.config_digest,0xcd,32);memset(scoped_message.body.inventory_digest,0xef,32);
	valid_subjects(&scoped_message.body.config.objects.paths.subjects);
	scoped_message.body.config.objects.paths.subjects.flags=SKP_SUBJECT_EXEMPT_ROOT;
	scoped_message.body.config.objects.paths.subjects.profile_count=2;
	scoped_message.body.config.objects.paths.subjects.profiles[1]=7;
	scoped_message.body.config.objects.paths.subjects.binding_count=1;
	scoped_message.body.config.objects.paths.subjects.bindings[0].uid=10001;
	scoped_message.body.config.objects.paths.subjects.bindings[0].profile_id=7;
	scoped_message.body.config.objects.paths.subjects.whitelist_count=1;
	scoped_message.body.config.objects.paths.subjects.whitelist[0]=10001;
	scoped_message.body.config.version=scoped_message.body.config.objects.version=scoped_message.body.config.objects.paths.version=1;
	scoped_message.body.config.objects.paths.path_count=1;
	strcpy(scoped_message.body.config.objects.paths.rules[0].path,"/fixture/hidden");
	scoped_message.body.config.objects.kstat_count=scoped_message.body.config.objects.map_count=1;
	strcpy(scoped_message.body.config.objects.kstats[0].path,"/fixture/a");
	scoped_message.body.config.objects.kstats[0].values.flags=1;scoped_message.body.config.objects.kstats[0].values.ino=7001;
	strcpy(scoped_message.body.config.objects.maps[0].path,"/fixture/a");
	scoped_message.body.config.redirect_count=1;scoped_message.body.config.mount_count=2;
	strcpy(scoped_message.body.config.redirects[0].source,"/fixture/source");strcpy(scoped_message.body.config.redirects[0].target,"/fixture/target");
	strcpy(scoped_message.body.config.mounts[0].path,"/fixture/mount-source");strcpy(scoped_message.body.config.mounts[1].path,"/fixture/mount-target");
	scoped_message.scopes.version=1;scoped_message.scopes.path_count=1;scoped_frame();
	for(i=0;i<9;++i){
		bad_scoped=scoped_message;
		if(i==0)bad_scoped.scopes.version=2;
		if(i==1)bad_scoped.scopes.path_count=0;
		if(i==2)bad_scoped.scopes.reserved=1;
		if(i==3)bad_scoped.scopes.rules[0].kind=2;
		if(i==4)bad_scoped.scopes.rules[0].whitelist_count=1;
		if(i==5)bad_scoped.scopes.rules[127].kind=1;
		if(i==6)bad_scoped.body.config_revision=0;
		if(i==7)memset(bad_scoped.body.request_id,0,16);
		if(i==8)bad_scoped.body.flags=2;
		before=active_policy;generation=policy_generation;old_prepares=prepares;
		expect(skp_policy_write(&fd,(const char*)&bad_scoped,sizeof(bad_scoped),NULL)==-EINVAL&&
		       active_policy==before&&policy_generation==generation&&prepares==old_prepares&&owner_a.refs==1,
		       "invalid scoped metadata/table rejected before VFS and owner refs");
	}
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message)-1,NULL)==-EMSGSIZE,"truncated scoped table rejected");
	current=&child_task;
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==-EACCES,"inherited FD cannot publish scoped rules");current=&owner_a;
	fail_scope_alloc=1;old_prepares=prepares;
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==-ENOMEM&&!active_policy&&owner_a.refs==1&&prepares==old_prepares,"large scope allocation failure unwinds held task before resolution");fail_scope_alloc=0;
	fail_prepare=1;
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==-ENOENT&&!active_policy&&owner_a.refs==1,"failed scoped VFS preparation frees copied scope and held owner");fail_prepare=0;
	race_prepare=1;generation=policy_generation;
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==-ESTALE&&!active_policy&&owner_a.refs==1&&policy_generation==generation+1,"scoped second CAS never publishes partial selectors");scoped_frame();
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==sizeof(scoped_message),"cmd7 all-inherit table is a valid complete publication");
	scoped_status("inherit");scoped_query(10001,false,false);scoped_query(10004,true,true);
	current=&owner_a;current_test_uid=0;
	scoped_message.scopes.rules[0].kind=SKP_PATH_SCOPE_CUSTOM;
	scoped_message.scopes.rules[0].mode=SKP_SUBJECT_BLACKLIST;
	scoped_message.scopes.rules[0].flags=SKP_SUBJECT_EXEMPT_ALL;
	scoped_message.scopes.rules[0].blacklist_count=1;scoped_message.scopes.rules[0].blacklist[0]=10001;
	scoped_frame();expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==sizeof(scoped_message),"custom path and canonical five-family snapshot publish together");
	scoped_status("custom");scoped_query(10001,true,false);scoped_query(10004,false,true);
	scoped_message.scopes.rules[0].blacklist[0]=10002;
	scoped_query(10001,true,false);
	expect(active_policy->path_scopes->rules[0].blacklist[0]==10001,"published selectors are immutable deep copies of caller input");
	scoped_message.scopes.rules[0].blacklist[0]=10001;
	manager=1;scoped_query(10001,false,false);manager=0;
	current=&owner_b;current_test_uid=0;expect(!skp_policy_open(NULL,&other_fd),"second root manager can inspect scoped owner");scoped_frame();old_prepares=prepares;
	expect(skp_policy_write(&other_fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==-EBUSY&&prepares==old_prepares,"other scoped owner rejected before filesystem work");
	current=&owner_a;managed_message.body=scoped_message.body;frame(&managed_message,sizeof(managed_message),SKP_POLICY_REPLACE_MANAGED);
	expect(skp_policy_write(&fd,(const char*)&managed_message,sizeof(managed_message),NULL)==-EOPNOTSUPP,"cmd6 cannot silently discard active path selectors");
	before=active_policy;old_publications=publications;bad_scoped=scoped_message;bad_scoped.scopes.rules[0].blacklist[127]=9;
	expect(skp_policy_write(&fd,(const char*)&bad_scoped,sizeof(bad_scoped),NULL)==-EINVAL&&active_policy==before&&publications==old_publications&&owner_a.refs==2,"invalid replacement leaves whole prior selector publication and owner refs intact");
	memset(&scoped_message.scopes.rules[0],0,sizeof(scoped_message.scopes.rules[0]));scoped_message.scopes.rules[0].kind=1;
	strcpy(scoped_message.body.config.objects.paths.rules[0].path,"/fixture/proc-alias");scoped_frame();old_publications=publications;
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==-EBUSY&&publications==old_publications&&active_policy==before&&owner_a.refs==2,"custom root selector cannot bypass bootstrap protection even when global root exempt");
	memset(scoped_message.body.config.objects.paths.rules[0].path,0,SKP_GROUP_PATH_LEN);strcpy(scoped_message.body.config.objects.paths.rules[0].path,"/fixture/hidden");scoped_frame();
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==sizeof(scoped_message),"custom whitelist can override root exemption on ordinary paths");
	scoped_query(0,true,false);
	fake_boottime_ns=active_policy->managed.facts_deadline_ns;
	scoped_status("expired");scoped_query(0,false,false);scoped_query(10004,false,false);
	current=&owner_a;current_test_uid=0;
	expect(!skp_policy_release(NULL,&fd)&&owner_a.refs==1,"scoped owner FD close releases session reference");
	scoped_status("closed");scoped_query(10004,false,false);
	current=&owner_a;current_test_uid=0;expect(!skp_policy_open(NULL,&fd),"scoped owner reopens fresh session without reviving old facts");
	scoped_query(0,false,false);current=&owner_a;current_test_uid=0;
	memset(&scoped_message.body.config,0,sizeof(scoped_message.body.config));valid_subjects(&scoped_message.body.config.objects.paths.subjects);
	scoped_message.body.config.version=scoped_message.body.config.objects.version=scoped_message.body.config.objects.paths.version=1;scoped_message.body.flags=0;
	memset(&scoped_message.scopes,0,sizeof(scoped_message.scopes));scoped_message.scopes.version=1;scoped_frame();
	expect(skp_policy_write(&fd,(const char*)&scoped_message,sizeof(scoped_message),NULL)==sizeof(scoped_message),"empty disabled cmd7 preserves explicit scope-format ownership");
	scoped_status("disabled");managed_message.body=scoped_message.body;frame(&managed_message,sizeof(managed_message),6);
	expect(skp_policy_write(&fd,(const char*)&managed_message,sizeof(managed_message),NULL)==-EOPNOTSUPP,"even empty disabled scoped format rejects cmd6 downgrade");
	memset(&subject_message.policy,0,sizeof(subject_message.policy));frame(&subject_message,sizeof(subject_message),2);
	expect(skp_policy_write(NULL,(const char*)&subject_message,sizeof(subject_message),NULL)==sizeof(subject_message)&&!active_policy&&owner_a.refs==1,"explicit upstream reset releases scoped memory and held owner");
	frame(&managed_message,sizeof(managed_message),6);
	expect(skp_policy_write(&fd,(const char*)&managed_message,sizeof(managed_message),NULL)==sizeof(managed_message)&&!active_policy->path_scopes,"cmd6 works unchanged after deliberate reset");
	memset(&subject_message.policy,0,sizeof(subject_message.policy));frame(&subject_message,sizeof(subject_message),2);
	expect(skp_policy_write(NULL,(const char*)&subject_message,sizeof(subject_message),NULL)==sizeof(subject_message),"scoped integration cleanup resets complete active snapshot");
	expect(!skp_policy_release(NULL,&fd)&&!skp_policy_release(NULL,&other_fd)&&!owner_a.refs&&!owner_b.refs&&!manager_count,"scoped fixtures drain every session and task reference");
}
int main(void)
{
	struct skp_kstat_query_result k;
	struct skp_map_query_result m;
	struct skp_redirect_query_result r;
	struct skp_mount_query_result mt;
	struct skp_fdinfo_query_result fd;
	struct skp_policy_snapshot *before;
	unsigned int count, i;
	bool hidden, applies;
	struct super_block sb = {.s_dev = 123};
	struct inode inode = { .i_sb = &sb, .i_ino = 456 };

	expect(skp_policy_kstat_query(123, 456, &k) == SKP_OBJECT_UPSTREAM && !k.matched,
	       "no snapshot pure upstream disposition");
	expect(skp_policy_map_query(123, 456, &m) == SKP_OBJECT_UPSTREAM, "map pure upstream");
	status_case("initial-upstream");
 expect(skp_policy_kstat_maps_query(123,456,4,&k) == SKP_OBJECT_UPSTREAM && !k.matched, "maps priority query upstream unchanged");
 expect(skp_policy_redirect_query(123, 789, 3, 31, 0, &r) == SKP_OBJECT_UPSTREAM && !r.matched, "redirect upstream without snapshot");
 expect(skp_policy_mount_query(1031, 31, 1, &mt) == SKP_OBJECT_UPSTREAM && !mt.hidden, "mount upstream without snapshot");
 expect(skp_policy_fdinfo_query(790, 32, &fd) == SKP_OBJECT_UPSTREAM && !fd.rewrite_ino, "fdinfo upstream without snapshot");
	valid_subjects(&object_message.config.paths.subjects);
	object_message.config.paths.version = 1; object_message.config.version = 1;
	object_message.config.kstat_count = object_message.config.map_count = 1;
	strcpy(object_message.config.kstats[0].path, "/fixture/a");
	strcpy(object_message.config.maps[0].path, "/fixture/a");
	object_message.config.kstats[0].values.flags = 1;
	object_message.config.kstats[0].values.ino = 9001;
	frame(&object_message, sizeof(object_message), SKP_POLICY_REPLACE_OBJECTS);
	fail_pin = 1;
	expect(write_object() == -EBUSY && !active_policy && !policy_generation &&
	       !arm_kstats && !arm_maps, "failed module pin forbids arming and publication");
	fail_pin = 0;
	expect(write_object() == sizeof(object_message), "first full publication succeeds at legacy counts zero");
	expect(policy_generation == 1 && publications == 1 && graces == 1, "one complete publication and generation");
	expect(pins == 2 && arm_kstats == 1 && arm_maps == 1, "pin before first object arming");
	expect(skp_policy_paths_active(), "objects uses grouped writer protection");
	status_case("first-objects");
 current_test_uid = 10001;
 expect(skp_policy_kstat_maps_query(123,456,4,&k) == SKP_OBJECT_GROUPED && k.matched && k.values.ino == 9001, "stage3 maps kstat unchanged");
 expect(skp_policy_redirect_query(123, 789, 3, 31, 0, &r) == SKP_OBJECT_GROUPED && !r.matched, "objects authoritative empty redirect");
 expect(skp_policy_mount_query(1031, 31, 1, &mt) == SKP_OBJECT_GROUPED && !mt.hidden && !mt.shown_id, "objects authoritative empty mounts");
 expect(skp_policy_fdinfo_query(790, 32, &fd) == SKP_OBJECT_GROUPED && !fd.rewrite_ino && fd.ino == 790 && fd.mnt_id == 32, "objects fdinfo unchanged grouped");
	malformed_frames();
	current_test_uid = 10001;
	expect(skp_policy_kstat_query(123, 456, &k) == SKP_OBJECT_GROUPED && k.matched &&
	       k.values.ino == 9001 && k.generation == 1, "kstat copied from canonical snapshot");
	expect(skp_policy_map_query(123, 456, &m) == SKP_OBJECT_GROUPED && m.hidden && m.generation == 1,
	       "map matches same publication");
	expect(skp_policy_kstat_query(123, 457, &k) == SKP_OBJECT_GROUPED && !k.matched && !k.values.ino,
	       "grouped no match zeroes copied payload");
	expect(skp_policy_map_query(124, 456, &m) == SKP_OBJECT_GROUPED && !m.hidden, "exact dev authoritative miss");
	manager = 1;
	expect(skp_policy_kstat_query(123, 456, &k) == SKP_OBJECT_GROUPED && !k.matched, "manager exemption");
	manager = 0;
	expect(skp_policy_override(&applies) && !applies, "unmigrated generic families remain off");
	before = active_policy; count = prepares;
	valid_subjects(&path_message.config.subjects); path_message.config.version = 1;
	frame(&path_message, sizeof(path_message), SKP_POLICY_REPLACE_PATHS); current_test_uid = 0;
	expect(skp_policy_write(NULL, (const char *)&path_message, sizeof(path_message), NULL) == -EOPNOTSUPP,
	       "old paths cannot erase kstat map");
	expect(active_policy == before && policy_generation == 1, "old client rejection preserves complete snapshot");
	valid_subjects(&subject_message.policy);
	frame(&subject_message, sizeof(subject_message), SKP_POLICY_REPLACE);
	expect(skp_policy_write(NULL, (const char *)&subject_message, sizeof(subject_message), NULL) == -EOPNOTSUPP,
	       "old subjects cannot erase full snapshot");
	count = prepares;
	object_message.expected_generation = 0;
	expect(write_object() == -ESTALE && prepares == count && active_policy == before, "stale precheck avoids VFS");
	object_message.expected_generation = policy_generation;
	fail_prepare = 1;
	expect(write_object() == -ENOENT && active_policy == before && policy_generation == 1, "resolver failure no publish");
	fail_prepare = 0; race_prepare = 1;
	expect(write_object() == -ESTALE && active_policy == before && policy_generation == 2 && publications == 1,
	       "concurrent generation invalidates prepared candidate without replay");
	frame(&object_message, sizeof(object_message), SKP_POLICY_REPLACE_OBJECTS);
	object_message.config.paths.path_count = 1;
	strcpy(object_message.config.paths.rules[0].path, "/fixture/readlink");
	fail_arm = 1;
	expect(write_object() == -EBUSY && active_policy == before && policy_generation == 2,
	       "arming failure preserves old snapshot; module remains pinned");
	fail_arm = 0;
	object_message.config.paths.path_count = 0;
	memset(object_message.config.paths.rules, 0, sizeof(object_message.config.paths.rules));
	object_message.config.kstats[0].values.ino = 9002;
	expect(write_object() == sizeof(object_message), "replacement publishes once");
	current_test_uid = 10001;
	expect(skp_policy_kstat_query(123, 456, &k) == SKP_OBJECT_GROUPED && k.matched && k.values.ino == 9002 && k.generation == 3,
	       "read sees only next whole generation");
	/* Repeated caller identities select groups in the same loaded pointer. */
	frame(&object_message, sizeof(object_message), SKP_POLICY_REPLACE_OBJECTS);
	test_subjects = &object_message.config.paths.subjects;
	test_subjects->profile_count = 2; test_subjects->profiles[1] = 7;
	test_subjects->binding_count = 1; test_subjects->bindings[0].uid = 10002;
	test_subjects->bindings[0].profile_id = 7;
	expect(write_object() == sizeof(object_message), "publish group with authoritative empty families");
	status_case("grouped-objects");
	for (i = 0; i < 100; ++i) {
		current_test_uid = (i & 1) ? 10001 : 10002;
		expect(skp_policy_kstat_query(123, 456, &k) == SKP_OBJECT_GROUPED && k.matched == (i & 1), "group selection atomic");
		expect(skp_policy_map_query(123, 456, &m) == SKP_OBJECT_GROUPED && m.hidden == (i & 1), "same group across families");
	}
	/* Explicit reset is the only old-client escape hatch. */
	memset(&subject_message, 0, sizeof(subject_message));
	frame(&subject_message, sizeof(subject_message), SKP_POLICY_USE_UPSTREAM); current_test_uid = 0;
	expect(skp_policy_write(NULL, (const char *)&subject_message, sizeof(subject_message), NULL) == sizeof(subject_message), "explicit reset");
	expect(!active_policy && !skp_policy_paths_active() && policy_module_pinned, "reset does not promise hot unload");
	status_case("reset-upstream");
	valid_subjects(&subject_message.policy); frame(&subject_message, sizeof(subject_message), SKP_POLICY_REPLACE);
	expect(skp_policy_write(NULL, (const char *)&subject_message, sizeof(subject_message), NULL) == sizeof(subject_message), "legacy subject mode still supported");
	status_case("legacy-subjects");
 current_test_uid = 10001;
 expect(skp_policy_kstat_maps_query(123,456,4,&k) == SKP_OBJECT_LEGACY_SUBJECT && k.legacy_allowed, "legacy maps kstat unchanged");
 current_test_uid = 10001;
 expect(skp_policy_redirect_query(123,789,3,31,0,&r) == SKP_OBJECT_LEGACY_SUBJECT && r.legacy_allowed, "redirect legacy decision");
 expect(skp_policy_mount_query(1031,31,1,&mt) == SKP_OBJECT_LEGACY_SUBJECT && mt.legacy_allowed, "mount legacy decision");
 expect(skp_policy_fdinfo_query(790,32,&fd) == SKP_OBJECT_LEGACY_SUBJECT && fd.legacy_allowed, "fdinfo legacy decision");
	current_test_uid = 10001;
	expect(skp_policy_kstat_query(123, 456, &k) == SKP_OBJECT_LEGACY_SUBJECT && k.legacy_allowed, "legacy subject decision copied without second snapshot");
	manager = 1;
	expect(skp_policy_map_query(123, 456, &m) == SKP_OBJECT_LEGACY_SUBJECT && !m.legacy_allowed, "legacy manager exemption"); manager = 0;
	/* Switch through upstream to the old path mode; new families stay empty. */
	memset(&subject_message.policy, 0, sizeof(subject_message.policy));
	frame(&subject_message, sizeof(subject_message), SKP_POLICY_USE_UPSTREAM); current_test_uid = 0;
	expect(skp_policy_write(NULL, (const char *)&subject_message, sizeof(subject_message), NULL) > 0, "second reset");
	frame(&path_message, sizeof(path_message), SKP_POLICY_REPLACE_PATHS);
	expect(skp_policy_write(NULL, (const char *)&path_message, sizeof(path_message), NULL) > 0, "old path command preserved");
	status_case("old-paths");
 expect(skp_policy_kstat_maps_query(123,456,4,&k) == SKP_OBJECT_GROUPED && !k.matched, "old paths maps kstat authoritative empty");
 expect(skp_policy_redirect_query(123,789,3,31,0,&r) == SKP_OBJECT_GROUPED && !r.matched, "old paths authoritative empty redirect");
 expect(skp_policy_mount_query(1031,31,1,&mt) == SKP_OBJECT_GROUPED && !mt.hidden && !mt.shown_id, "old paths authoritative empty mount");
	expect(skp_policy_kstat_query(123, 456, &k) == SKP_OBJECT_GROUPED && !k.matched, "old paths suppress legacy kstat");
	expect(skp_policy_map_query(123, 456, &m) == SKP_OBJECT_GROUPED && !m.hidden, "old paths suppress legacy maps");
	expect(skp_policy_paths_inode_override(&inode, &hidden) && !hidden, "empty path negative");
	expect(skp_policy_paths_dirent_override(456, "a", &hidden) && !hidden, "empty dirent negative");
	before = active_policy; current_test_uid = 10001;
	expect(write_object() == -ESTALE, "old object request remains stale");
	current_test_uid = 10001;
	expect(skp_policy_write(NULL, (const char *)&object_message, sizeof(object_message), NULL) == -EACCES && active_policy == before,
	       "actual nonroot denied even for active policy");
	current_test_uid = 0;
	expect(skp_policy_write(NULL, (const char *)&object_message, sizeof(object_message) - 1, NULL) == -EMSGSIZE, "exact frame size");

 /* Upgrade from the legacy path format into one five-family candidate. */
 full_message.config.objects = object_message.config;
 full_message.config.objects.kstat_count = 2;
 strcpy(full_message.config.objects.kstats[1].path,"/fixture/target");
 full_message.config.objects.kstats[1].values.flags = 1;
 full_message.config.objects.kstats[1].values.ino = 7777;
 full_message.config.version = 1;
 full_message.config.redirect_count = 1; full_message.config.mount_count = 2;
 strcpy(full_message.config.redirects[0].source, "/fixture/source");
 strcpy(full_message.config.redirects[0].target, "/fixture/target");
 strcpy(full_message.config.mounts[0].path, "/fixture/mount-source");
 strcpy(full_message.config.mounts[1].path, "/fixture/mount-target");
 frame(&full_message, sizeof(full_message), SKP_POLICY_REPLACE_FULL);
 for (i = 0; i < 12; ++i) {
  struct skp_full_objects_message *bad = (void *)invalid_frame;
  memcpy(invalid_frame,&full_message,sizeof(full_message));
  if (i == 0) bad->config.version = 0;
  if (i == 1) bad->config.redirect_count = SKP_GROUP_REDIRECTS_MAX + 1;
  if (i == 2) bad->config.mount_count = SKP_GROUP_MOUNTS_MAX + 1;
  if (i == 3) bad->config.reserved = 1;
  if (i == 4) bad->config.redirects[0].flags = 1;
  if (i == 5) bad->config.redirects[0].profile_id = 99;
  if (i == 6) strcpy(bad->config.redirects[0].target,bad->config.redirects[0].source);
  if (i == 7) bad->config.redirects[SKP_GROUP_REDIRECTS_MAX - 1].flags = 1;
  if (i == 8) bad->config.mounts[0].flags = 1;
  if (i == 9) bad->config.mounts[0].profile_id = 99;
  if (i == 10) strcpy(bad->config.mounts[0].path,"/a/../b");
  if (i == 11) bad->config.mounts[SKP_GROUP_MOUNTS_MAX - 1].flags = 1;
  reject_frame(invalid_frame,sizeof(full_message),-EINVAL);
 }
 count = publications; before = active_policy;
 fail_prepare = 1;
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == -ENOENT &&
        active_policy == before && publications == count, "full resolver failure keeps previous");
 fail_prepare = 0; fake_full_stable = false;
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == -ESTALE &&
        active_policy == before && publications == count, "full topology changed before publish");
 fake_full_stable = true; fail_redirect_arm = 1;
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == -EBUSY &&
        active_policy == before && publications == count, "redirect arm failure no publication");
 fail_redirect_arm = 0; fail_mount_arm = 1;
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == -EBUSY &&
        active_policy == before && publications == count, "mount arm failure no publication");
 fail_mount_arm = 0; fail_second_stability = true; stability_checks = 0;
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == -ESTALE &&
        active_policy == before && publications == count && stability_checks == 2,
        "topology changed during hook arming rejected by second stability check");
 fail_second_stability = false; race_prepare = 1;
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == -ESTALE &&
        active_policy == before && publications == count && policy_generation == 9, "full second CAS rejects raced candidate");
 frame(&full_message,sizeof(full_message),SKP_POLICY_REPLACE_FULL);
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == sizeof(full_message) &&
        publications == count + 1 && policy_generation == 10, "five families publish exactly once");
 expect(!active_policy->full->temporary && temporary_frees >= 5, "temporary refs detached then released after unlock");
 status_case("full-objects");
 current_test_uid = 10001;
 expect(skp_policy_redirects_active(), "full redirect availability");
 expect(skp_policy_kstat_query(123,790,&k) == SKP_OBJECT_GROUPED && k.matched && k.values.ino == 7777,
        "generic target stat kstat remains active");
 expect(skp_policy_kstat_maps_query(123,790,4,&k) == SKP_OBJECT_GROUPED && !k.matched && !k.values.ino && k.generation == 10,
        "redirect reverse priority suppresses competing maps kstat from same snapshot");
 expect(skp_policy_kstat_maps_query(123,790,5,&k) == SKP_OBJECT_GROUPED && k.matched && k.values.ino == 7777,
        "nonmatching redirect generation retains maps kstat");
 expect(skp_policy_kstat_maps_query(123,456,4,&k) == SKP_OBJECT_GROUPED && k.matched && k.values.ino == 9002,
        "ordinary maps kstat unchanged beside redirect");
 current_test_uid = 10002;
 expect(skp_policy_kstat_maps_query(123,790,4,&k) == SKP_OBJECT_GROUPED && !k.matched,
        "empty other profile never consumes kstat or redirect");
 current_test_uid = 10001; manager = 1;
 expect(skp_policy_kstat_maps_query(123,790,4,&k) == SKP_OBJECT_GROUPED && !k.matched,
        "precise manager exempt from maps priority and kstat");
 manager = 0;
 expect(skp_policy_kstat_query(123,456,&k) == SKP_OBJECT_GROUPED && k.matched && k.values.ino == 9002 && k.generation == 10, "full inherited kstat same generation");
 expect(skp_policy_map_query(123,456,&m) == SKP_OBJECT_GROUPED && m.hidden && m.generation == 10, "full inherited map same generation");
 expect(skp_policy_redirect_query(123,789,3,31,SKP_REDIRECT_FORWARD,&r) == SKP_OBJECT_GROUPED && r.matched &&
        !strcmp(r.path,"/fixture/target") && !strcmp(r.target_path,"/fixture/target") && r.source_ino == 789 &&
        r.source_mnt_id == 1 && r.source_statfs.f_type == 0x1234 && r.generation == 10, "full forward and mapped source ID copied");
 expect(skp_policy_redirect_query(123,790,4,32,SKP_REDIRECT_REVERSE,&r) == SKP_OBJECT_GROUPED && r.matched &&
        !strcmp(r.path,"/fixture/source"), "full reverse source path");
 expect(skp_policy_redirect_query(123,790,5,32,SKP_REDIRECT_REVERSE,&r) == SKP_OBJECT_GROUPED && !r.matched && !r.path[0], "exact generation miss clears path");
 expect(skp_policy_fdinfo_query(790,32,&fd) == SKP_OBJECT_GROUPED && fd.rewrite_ino && fd.ino == 789 &&
        fd.mnt_id == 1 && fd.generation == 10, "combined fdinfo identifies actual target before mount translation");
 expect(skp_policy_fdinfo_query(790,31,&fd) == SKP_OBJECT_GROUPED && !fd.rewrite_ino && fd.ino == 790 && fd.mnt_id == 1, "wrong target mount forbids redirect while exact mount translation remains");
 expect(skp_policy_mount_query(1031,31,1,&mt) == SKP_OBJECT_GROUPED && mt.hidden && mt.shown_id == 1 && mt.generation == 10, "full mount exact cookie");
 expect(skp_policy_mount_query(9999,31,1,&mt) == SKP_OBJECT_GROUPED && !mt.hidden && mt.shown_id == 31, "wrong mount cookie preserves actual");
 fake_topology_stable = false;
 expect(skp_policy_mount_query(1031,31,1,&mt) == SKP_OBJECT_GROUPED && mt.uncertain && !mt.hidden && !mt.shown_id, "changed topology preserves native via uncertain");
 expect(skp_policy_fdinfo_query(790,32,&fd) == SKP_OBJECT_GROUPED && fd.rewrite_ino && fd.ino == 789 && fd.mnt_id == 31, "uncertain topology keeps redirect identity but no mount map");
 fake_topology_stable = true;
 for (i = 0; i < 100; ++i) {
  current_test_uid = (i & 1) ? 10001 : 10002;
  expect(skp_policy_redirect_query(123,789,3,31,0,&r) == SKP_OBJECT_GROUPED && r.matched == (i & 1) && r.generation == 10, "profile scoped redirect same snapshot");
  expect(skp_policy_mount_query(1031,31,1,&mt) == SKP_OBJECT_GROUPED && mt.hidden == (i & 1) && mt.generation == 10, "profile scoped mount same snapshot");
 }
 manager = 1; current_test_uid = 10001;
 expect(skp_policy_redirect_query(123,789,3,31,0,&r) == SKP_OBJECT_GROUPED && !r.matched, "full manager exemption");
 expect(skp_policy_fdinfo_query(790,32,&fd) == SKP_OBJECT_GROUPED && !fd.rewrite_ino && fd.ino == 790 && fd.mnt_id == 32, "manager fdinfo exemption");
 manager = 0; current_test_uid = 0;
 /* Empty full mode is still a format barrier against every older writer. */
 memset(&full_message.config,0,sizeof(full_message.config));
 valid_subjects(&full_message.config.objects.paths.subjects);
 full_message.config.objects.paths.version = full_message.config.objects.version = full_message.config.version = 1;
 frame(&full_message,sizeof(full_message),SKP_POLICY_REPLACE_FULL);
 expect(skp_policy_write(NULL,(const char *)&full_message,sizeof(full_message),NULL) == sizeof(full_message), "empty five-family replacement");
 status_case("empty-full"); before = active_policy;
 expect(!skp_policy_redirects_active(), "empty redirect inactive without legacy fallback");
 valid_subjects(&subject_message.policy); frame(&subject_message,sizeof(subject_message),SKP_POLICY_REPLACE);
 frame(&path_message,sizeof(path_message),SKP_POLICY_REPLACE_PATHS);
 frame(&object_message,sizeof(object_message),SKP_POLICY_REPLACE_OBJECTS);
 expect(skp_policy_write(NULL,(const char *)&subject_message,sizeof(subject_message),NULL) == -EOPNOTSUPP, "empty full rejects subject downgrade");
 expect(skp_policy_write(NULL,(const char *)&path_message,sizeof(path_message),NULL) == -EOPNOTSUPP, "empty full rejects path downgrade");
 expect(skp_policy_write(NULL,(const char *)&object_message,sizeof(object_message),NULL) == -EOPNOTSUPP && active_policy == before && policy_generation == 11, "empty full rejects object downgrade");
 memset(&subject_message.policy,0,sizeof(subject_message.policy)); frame(&subject_message,sizeof(subject_message),SKP_POLICY_USE_UPSTREAM);
 expect(skp_policy_write(NULL,(const char *)&subject_message,sizeof(subject_message),NULL) == sizeof(subject_message), "explicit reset leaves full mode");
 frame(&object_message,sizeof(object_message),SKP_POLICY_REPLACE_OBJECTS);
 expect(write_object() == sizeof(object_message), "old format usable after explicit reset");
 before = active_policy;
	count = prepares; policy_generation = U64_MAX;
	object_message.expected_generation = U64_MAX;
	expect(write_object() == -EOVERFLOW && prepares == count && active_policy == before, "generation overflow rejected before preparation");
	active_policy = NULL; skp_policy_snapshot_free(before);
	policy_generation = 100;
	managed_tests();
	scoped_tests();
	expect(!locks && !rcu_depth && frees > 0, "all guards and candidates drained");
	printf("POLICY_ADAPTER_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n", checks);
	return 0;
}
