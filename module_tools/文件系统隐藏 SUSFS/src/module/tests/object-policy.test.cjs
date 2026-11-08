'use strict';

const assert = require('node:assert/strict');
const ObjectPolicy = require('../webroot/object-policy.js');
const SubjectPolicy = require('../webroot/subject-policy.js');

const model = ObjectPolicy.createModel();
model.load(ObjectPolicy.defaults());
assert.equal(model.dirty(), false);
assert.throws(() => model.removeProfile(0), /不可删除/);

const first = model.addProfile('First');
const second = model.addProfile('Second');
model.upsert(first.id, 'path', '/fixture/first');
model.upsert(second.id, 'map', '/fixture/second');
const specified = { ...SubjectPolicy.defaults(), mode: 'blacklist', blacklist_packages: ['org.susfs4skp.probe'] };
model.setProfileSubjects(first.id, specified);
model.setProfileSubjects(second.id, specified);
assert.deepEqual(model.profileSubjects(first.id), specified);
assert.deepEqual(model.profileSubjects(second.id), specified);
assert.deepEqual(model.getProfile(first.id).packages, []);

const returned = model.profileSubjects(first.id);
returned.blacklist_packages.length = 0;
assert.deepEqual(model.profileSubjects(first.id).blacklist_packages, ['org.susfs4skp.probe']);
const exclusion = { ...SubjectPolicy.defaults(), exempt_root: false, whitelist_packages: ['android'] };
model.setProfileSubjects(first.id, exclusion);
assert.deepEqual(model.profileSubjects(second.id), specified);
assert.deepEqual(ObjectPolicy.normalize(model.payload()).profiles[1].subjects, exclusion);

// Existing schema10 group bindings remain intact until that group is edited.
const legacy = ObjectPolicy.defaults();
delete legacy.profiles[0].subjects;
const group = ObjectPolicy.profile(4, 'Legacy');
delete group.subjects;
group.packages = ['org.susfs4skp.probe'];
group.rules.paths = ['/fixture/generated', '/fixture/custom'];
legacy.profiles.push(group);
const generated = { ...SubjectPolicy.defaults(), mode: 'blacklist', blacklist_packages: [...group.packages], exempt_root: false, exempt_system_processes: false, exempt_system_apps: false };
legacy.path_scopes = [
  { profile_id: 4, path: '/fixture/generated', subjects: generated },
  { profile_id: 4, path: '/fixture/custom', subjects: specified },
];
model.load(legacy);
assert.deepEqual(model.profileSubjects(4), generated);
assert.equal(model.dirty(), false);
assert.equal(model.getProfile(4).subjects, undefined);
model.setProfileSubjects(4, exclusion);
assert.deepEqual(model.getProfile(4).packages, []);
assert.deepEqual(model.config.path_scopes.map(scope => scope.path), ['/fixture/custom']);
assert.deepEqual(model.profileSubjects(4), exclusion);
// Editing the default policy does not silently alter legacy global intent.
const oldGlobal = ObjectPolicy.clone(model.config.subjects);
model.setProfileSubjects(0, specified);
assert.deepEqual(model.profileSubjects(0), specified);
assert.deepEqual(model.config.subjects, oldGlobal);

// The old package helper cannot leave a new group's selector stale.
model.setProfilePackages(4, ['org.susfs4skp.fixture']);
assert.deepEqual(model.profileSubjects(4).blacklist_packages, ['org.susfs4skp.fixture']);
assert.equal(model.profileSubjects(4).mode, 'blacklist');
assert.throws(() => ObjectPolicy.normalize({ ...legacy, profiles: [{ ...group, subjects: specified }] }), /旧版应用绑定/);
const content = ObjectPolicy.createModel();
content.load(ObjectPolicy.defaults());
content.upsert(0, 'redirect', { source: '/proc/cpuinfo', target: '/private/cpu.txt', mode: 'content' });
assert.equal(content.payload().schema, 11);
assert.equal(content.payload().mode, 'groups');
assert.equal(content.payload().profiles[0].rules.redirects[0].mode, 'content');
content.didSave(content.payload());
assert.equal(content.dirty(), false);
content.upsert(0, 'redirect', { ...content.config.profiles[0].rules.redirects[0], target: '/private/new.txt' }, '/proc/cpuinfo');
assert.equal(content.payload().profiles[0].rules.redirects[0].mode, 'content');
for (const path of ['/fixtures/source', '/proc/uptime', '/proc/self/status']) {
  const loaded = ObjectPolicy.clone(content.payload());
  loaded.profiles[0].rules.redirects[0].source = path;
  assert.equal(ObjectPolicy.normalize(loaded).profiles[0].rules.redirects[0].source, path, 'load preserves configured paths independently of running kernel capability');
}
assert.throws(() => content.upsert(0, 'redirect', {source:'relative',target:'/private/cpu.txt',mode:'content'}), /绝对路径/);
assert.throws(() => content.upsert(0, 'redirect', {source:'/',target:'/private/cpu.txt',mode:'content'}), /绝对路径/);
const oldKernel = {content_redirect:true,content_sources:['/proc/cpuinfo','/proc/meminfo','/proc/version']};
assert.equal(ObjectPolicy.contentCapabilities(oldKernel).regularFiles, false);
assert.equal(ObjectPolicy.contentSourceError('/proc/cpuinfo', oldKernel), '');
assert.match(ObjectPolicy.contentSourceError('/fixtures/source', oldKernel), /尚不支持普通文件来源/);
assert.match(ObjectPolicy.contentSourceError('/proc/uptime', oldKernel), /不支持此 proc/);
const newKernel = {...oldKernel,content_regular_files:true,content_regular_filesystems:['ext4','tmpfs'],content_sources:[...oldKernel.content_sources,'/proc/uptime']};
assert.equal(ObjectPolicy.contentSourceError('/fixtures/source', newKernel), '');
assert.equal(ObjectPolicy.contentSourceError('/proc/uptime', newKernel), '');
assert.match(ObjectPolicy.contentSourceError('/proc/self/status', newKernel), /不支持此 proc/);
assert.match(ObjectPolicy.contentSourceError('/fixtures/source', {...oldKernel,content_regular_files:'true'}), /尚不支持普通文件来源/);
assert.match(ObjectPolicy.contentSourceError('/proc/cpuinfo', {}), /不支持只读内容替换/);
assert.match(ObjectPolicy.contentSourceError('/proc/cpuinfo', {content_redirect:false,content_disabled_reason:'kernel_6_6_disabled'}), /6\.6 内核暂未开放/);
assert.equal(ObjectPolicy.contentSourceError('/proc/cpuinfo', {content_redirect:true}), '', 'missing proc list falls back only to legacy reviewed nodes');
const invalidSchema = content.payload(); invalidSchema.schema = 10;
assert.throws(() => ObjectPolicy.normalize(invalidSchema), /旧版配置/);
const unknownMode = content.payload(); unknownMode.profiles[0].rules.redirects[0].mode = 'future';
assert.throws(() => ObjectPolicy.normalize(unknownMode), /未知重定向模式/);
assert.throws(() => ObjectPolicy.normalize({...ObjectPolicy.defaults(), schema: 15}), /不支持的配置版本/);
const withWebui=ObjectPolicy.createModel();
withWebui.load({...ObjectPolicy.defaults(),schema:13,webui:{no_background:true}});
assert.equal(withWebui.payload().webui.no_background,true);
withWebui.upsert(0,'directory_name','fixture');
assert.equal(withWebui.payload().schema,13,'name rules retain the newer settings schema');
assert.throws(()=>ObjectPolicy.normalize({...ObjectPolicy.defaults(),schema:13,webui:{no_background:'true'}}),/WebUI 设置无效/);
assert.throws(()=>ObjectPolicy.normalize({...ObjectPolicy.defaults(),webui:{no_background:true}}),/WebUI 设置无效/);
const upstream = content.payload(); upstream.mode = 'upstream';
assert.throws(() => ObjectPolicy.normalize(upstream), /需要分组模式/);
content.upsert(0, 'redirect', { source: '/proc/cpuinfo', target: '/private/new.txt', mode: 'path' }, '/proc/cpuinfo');
assert.equal(content.payload().schema, 10);
assert.equal(content.payload().profiles[0].rules.redirects[0].mode, undefined);

// Basename rules are explicit and preserve exact UTF-8 names independently of
// the running kernel. Legacy payloads remain accepted by pre-schema12 servers.
const names = ObjectPolicy.createModel();
const oldPayload = ObjectPolicy.defaults(); delete oldPayload.profiles[0].rules.directory_names;
names.load(oldPayload);
assert.deepEqual(names.config.profiles[0].rules.directory_names, []);
assert.equal(names.dirty(), false);
assert.equal(Object.hasOwn(names.payload().profiles[0].rules, 'directory_names'), false);
assert.equal(ObjectPolicy.kinds.find(kind => kind.id === 'directory_name').name, '名称匹配隐藏');
for (const name of ['bin.mt.plus', 'Bin.Mt.Plus', '目录', ' space ', 'literal*name[1]', 'a'.repeat(255), '中'.repeat(85), '🙂'.repeat(63)]) {
  assert.equal(ObjectPolicy.directoryNameError(name), '');
  names.upsert(0, 'directory_name', name);
}
assert.equal(names.payload().schema, 12);
assert.equal(names.payload().mode, 'groups');
assert.deepEqual(names.payload().profiles[0].rules.directory_names.slice(0, 4), ['bin.mt.plus', 'Bin.Mt.Plus', '目录', ' space ']);
for (const name of ['', '.', '..', '/data/bin.mt.plus', 'parent/child', 'bad\0name', 'a'.repeat(256), '中'.repeat(86), '🙂'.repeat(64), '\ud800', '\udfff']) {
  assert.ok(ObjectPolicy.directoryNameError(name), JSON.stringify(name));
  assert.throws(() => names.upsert(0, 'directory_name', name));
}
assert.throws(() => names.upsert(0, 'directory_name', 'bin.mt.plus'), /已有/);
names.didSave(names.payload());
assert.equal(names.dirty(), false);
assert.equal(ObjectPolicy.normalize(names.payload()).schema, 12);
const malformedNames = names.payload(); malformedNames.profiles[0].rules.directory_names = ['bad/name'];
assert.throws(() => ObjectPolicy.normalize(malformedNames), /完整名称/);
const invalidOldNames = names.payload(); invalidOldNames.schema = 11;
assert.throws(() => ObjectPolicy.normalize(invalidOldNames), /旧版配置/);
const upstreamNames = names.payload(); upstreamNames.mode = 'upstream';
assert.throws(() => ObjectPolicy.normalize(upstreamNames), /需要分组模式/);
assert.equal(ObjectPolicy.allowedKinds([{type: 'directory'}]).includes('directory_name'), false, 'file selection must not broaden a path into all matching names');
assert.equal(ObjectPolicy.allowedKinds([{type: 'file'}]).includes('directory_name'), false);
assert.deepEqual(ObjectPolicy.filePresentation('/fixtures/bin.mt.plus', names).indicators, [], 'a basename alone cannot infer directory type or confirmed application');
names.upsert(0, 'redirect', {source:'/proc/cpuinfo', target:'/private/cpu.txt', mode:'content'});
assert.equal(names.payload().schema, 12, 'adding content must retain the higher directory-name schema');
const nameGroup = names.addProfile('目录名组'); names.upsert(nameGroup.id, 'directory_name', 'group-only');
names.removeProfile(nameGroup.id);
assert.ok(names.config.profiles[0].rules.directory_names.includes('group-only'), 'deleting groups retains their basename rules in the default group');
for (const name of [...names.config.profiles[0].rules.directory_names]) names.remove(0, 'directory_name', name);
assert.equal(names.payload().schema, 11);
assert.equal(Object.hasOwn(names.payload().profiles[0].rules, 'directory_names'), false);
names.remove(0, 'redirect', '/proc/cpuinfo');
assert.equal(names.payload().schema, 10);
console.log('object-policy: PASS (group policies, legacy preservation, content replacement, exact UTF-8 directory names and schema compatibility)');
