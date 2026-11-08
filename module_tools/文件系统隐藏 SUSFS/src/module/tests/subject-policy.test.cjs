'use strict';

const assert = require('node:assert/strict');
const SubjectPolicy = require('../webroot/subject-policy.js');

const apps = [
  { package: 'org.susfs4skp.probe', uid: 10123, label: 'Fixture Probe', is_system: false },
  { package: 'org.susfs4skp.fixture.shared', uid: 10123, label: 'Fixture Shared UID', is_system: false, shared_uid: true },
  { package: 'org.susfs4skp.fixture.system', uid: 10124, label: 'Fixture System', is_system: true },
];

const metadata = {
  apps: apps.map(app => ({ ...app, iconPng: 'png-data', version: '1.0.0', status: 'ok' })),
};

const merged = SubjectPolicy.mergeMetadata(apps, metadata);
assert.equal(merged[0].iconPng, 'png-data');
assert.equal(merged[0].label, 'Fixture Probe');

const groups = SubjectPolicy.groups(merged, {
  ...SubjectPolicy.defaults(),
  mode: 'blacklist',
  blacklist_packages: ['org.susfs4skp.probe', 'org.susfs4skp.missing'],
});
const shared = groups.find(group => group.uid === 10123);
assert.equal(shared.shared, true);
assert.equal(shared.appCount, 2);
assert.equal(shared.allSelected, false);
assert.equal(groups.some(group => group.uninstalled && group.packageNames.includes('org.susfs4skp.missing')), true);

const selected = SubjectPolicy.toggle({ ...SubjectPolicy.defaults(), mode: 'blacklist' }, shared, true);
assert.deepEqual(selected.blacklist_packages, ['org.susfs4skp.fixture.shared', 'org.susfs4skp.probe']);
assert.equal(SubjectPolicy.modeInfo('whitelist').label, '排除模式');
assert.equal(SubjectPolicy.modeInfo('blacklist').broadExemptions, false);

const profiles = [
  { id: 0, packages: [] },
  { id: 1, packages: ['org.susfs4skp.probe'] },
];
const conflict = SubjectPolicy.validateSelection(profiles, apps, 2, shared);
assert.equal(conflict.ok, false);
assert.match(conflict.error, /共享 UID 10123/);
assert.equal(SubjectPolicy.validateSelection(profiles, apps, 2, [ 'org.susfs4skp.fixture.system' ]).ok, true);

const broad = SubjectPolicy.setBroadExemption(SubjectPolicy.defaults(), 'exempt_root', false);
assert.equal(broad.exempt_root, false);
assert.equal(SubjectPolicy.defaults().exempt_root, true);
console.log('subject-policy: PASS');
