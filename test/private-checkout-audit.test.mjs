import test from 'node:test';import assert from 'node:assert/strict';
import {AUDIT_FILES,scanSelectedEvidence} from '../src/private-checkout-audit.mjs';
const sourceSha='a'.repeat(40),scannerSha='b'.repeat(40);
const fixture=()=>AUDIT_FILES.map(path=>({path,content:path.endsWith('.yml')?
 'name: test\non: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  read:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Print\n        run: echo done\n':"export const example = 'safe';"}));
test('independent checker scans exactly nine critical files, no private code in report',()=>{
 const r=scanSelectedEvidence(fixture(),{sourceSha,scannerSha});
 assert.equal(r.coverage.length,9);assert.equal(r.counts.HIGH,0);
 assert.equal(r.status,'COMPLETE');assert.equal(r.productionRelease,'DENIED');
 assert.equal(JSON.stringify(r).includes("export const example"),false);
});
test('secret shaped literal is reported but never exposed',()=>{
 const f=fixture();f[0].content="const t='ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789ABCDEFGHIJ';";
 const r=scanSelectedEvidence(f,{sourceSha,scannerSha});
 assert.ok(r.counts.HIGH>=1);
 assert.equal(JSON.stringify(r).includes('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789ABCDEFGHIJ'),false);
});
test('incomplete scope never passes',()=>{
 assert.throws(()=>scanSelectedEvidence(fixture().slice(1),{sourceSha,scannerSha}),/COVERAGE/);
});
test('workflow unpinned action produces medium finding',()=>{
 const f=fixture();f[f.length-1].content=f.at(-1).content.replace('run: echo done','uses: actions/checkout@v4');
 const r=scanSelectedEvidence(f,{sourceSha,scannerSha});
 assert.ok(r.findings.some(x=>x.rule_id==='ACTION_UNPINNED'));
});
test('invalid commit SHA denied',()=>{
 assert.throws(()=>scanSelectedEvidence(fixture(),{sourceSha:'wrong',scannerSha}),/COVERAGE/);
});
