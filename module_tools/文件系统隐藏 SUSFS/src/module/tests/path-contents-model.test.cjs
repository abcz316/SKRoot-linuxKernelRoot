'use strict';
const assert = require('node:assert/strict');
const policy = require('../webroot/object-policy.js');
const config = policy.defaults();
config.schema = 14;
config.mode = 'groups';
config.webui = {no_background:true};
config.profiles[0].rules.paths = ['/legacy/folder', {path:'/fixture/folder',hide_contents:true}, {path:'/fixture/file',hide_contents:false}];
const model = policy.createModel();
model.load(config);
assert.equal(model.dirty(), false);
assert.deepEqual(model.payload().profiles[0].rules.paths, ['/legacy/folder',{path:'/fixture/folder',hide_contents:true},'/fixture/file']);
assert.equal(model.payload().schema,14);
assert.equal(policy.key('path',model.payload().profiles[0].rules.paths[1]),'/fixture/folder');
assert.match(policy.filePresentation('/fixture/folder',model).description,/仅隐藏文件夹内容/);
assert.throws(()=>model.upsert(0,'path',{path:'/fixture/folder',hide_contents:true}),/已有/);
model.upsert(0,'path',{path:'/fixture/folder',hide_contents:false},'/fixture/folder');
assert.equal(model.payload().profiles[0].rules.paths[1],'/fixture/folder');
assert.equal(model.payload().schema,13);
assert.equal(model.payload().webui.no_background,true);
for (const rule of [null,{},[],{path:'/fixture',hide_contents:'true'},{path:'/fixture',hide_contents:true,extra:true},{path:'relative',hide_contents:true},{path:'/bad\0name',hide_contents:true}])
  assert.throws(()=>model.upsert(0,'path',rule));
for (const schema of [10,11,12,13]) {
  const legacy=policy.clone(config);legacy.schema=schema;
  if(schema<13)delete legacy.webui;
  assert.throws(()=>policy.normalize(legacy),/旧版配置/);
}
const upstream=policy.clone(config);upstream.mode='upstream';
assert.throws(()=>policy.normalize(upstream),/需要分组模式/);
assert.equal(policy.pathHideRule('/ordinary',true,'file'),'/ordinary');
assert.deepEqual(policy.pathHideRule('/folder',true,'directory'),{path:'/folder',hide_contents:true});
assert.equal(policy.pathHideRule('/folder',false,'directory'),'/folder');
assert.deepEqual(policy.pathHideRule('/manual',true),{path:'/manual',hide_contents:true});
console.log('path-contents-model: PASS (legacy preserved, schema14 roundtrip, strict validation, mixed selection, mode edit and badge)');
