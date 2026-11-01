import test from 'node:test';
import assert from 'node:assert/strict';
import {assessRuntime,assessScanEvidence,inspectStrixArtifacts,sourceFingerprint} from '../tools/strix-lab-runner.mjs';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const goodReceipt=Object.freeze({
  endTime:'2026-11-01T11:30:00Z',
  reportedTarget:'/tmp/disposable-lab/public-source',
  expectedTarget:'/tmp/disposable-lab/public-source',
  spentUsd:0
});
const evaluated=options=>assessScanEvidence({...goodReceipt,...options});

const safe=()=>({
  CYBER_HAK_STRIX_LOCAL_RUN:'EXPLICITLY_APPROVED',
  CYBER_HAK_STRIX_ISOLATED_HOST:'CONFIRMED',
  STRIX_LLM:'ollama/qwen3-vl',
  LLM_API_BASE:'http://127.0.0.1:11434',
  CYBER_HAK_STRIX_EXPECTED_VERSION:'1.2.3',
  CYBER_HAK_STRIX_SIGNED_PERMIT_PATH:'/tmp/synthetic-owner-permit.json',
  CYBER_HAK_STRIX_OWNER_PUBLIC_KEY_PATH:'/tmp/synthetic-owner-spki.pem',
  CYBER_HAK_STRIX_OWNER_SPKI_SHA256:'a'.repeat(64),
  CYBER_HAK_STRIX_NONCE_STORE:'/tmp/synthetic-strix-nonce-store'
});

test('preflight never claims an exploit scan ran',()=>{
  const result=assessRuntime({},'--preflight');
  assert.equal(result.status,'PREFLIGHT_ONLY_NOT_SCANNED');
  assert.equal(result.externalEffects,0);
  assert(result.requirements.every(x=>x.state==='NOT_VERIFIED'));
});

test('live scan requires explicit separate owner authorization',()=>{
  const e=safe();delete e.CYBER_HAK_STRIX_LOCAL_RUN;
  assert.throws(()=>assessRuntime(e,'--run'),/OWNER_APPROVAL_REQUIRED/);
});

test('scan without isolated host is denied',()=>{
  const e=safe();delete e.CYBER_HAK_STRIX_ISOLATED_HOST;
  assert.throws(()=>assessRuntime(e,'--run'),/EGRESS_ISOLATION_NOT_ATTESTED/);
});

test('external model and remote API base are denied',()=>{
  const e=safe();e.STRIX_LLM='openai/gpt-5.4';
  assert.throws(()=>assessRuntime(e,'--run'),/LOCAL_OLLAMA_MODEL_REQUIRED/);
  const another=safe();another.LLM_API_BASE='https://api.example.com';
  assert.throws(()=>assessRuntime(another,'--run'),/LOOPBACK_LLM_BASE_REQUIRED/);
});

test('secret-bearing external providers or GitHub tokens are denied',()=>{
  for(const name of ['LLM_API_KEY','OPENAI_API_KEY','ANTHROPIC_API_KEY',
                      'GITHUB_TOKEN','GH_TOKEN','SUPABASE_SERVICE_ROLE_KEY',
                      'LLM_EXTRA_HEADERS']){
    const e=safe();e[name]='synthetic-test-string';
    assert.throws(()=>assessRuntime(e,'--run'),
      /PRIVILEGED_OR_EXTERNAL_SECRET_ENV_DENIED/,name);
  }
});

test('approved local plan still declares it has NOT run Strix',()=>{
  const result=assessRuntime(safe(),'--run');
  assert.equal(result.status,'LOCAL_LAB_ADMISSIBLE_NOT_SCANNED');
  assert.equal(result.target,'DISPOSABLE_PUBLIC_SOURCE_COPY_ONLY');
  assert.equal(result.externalEffects,0);
});

test('unknown mode is denied',()=>{
  assert.throws(()=>assessRuntime(safe(),'--target=https://server.example.com'),
    /UNSUPPORTED_STRIX_MODE/);
});


test('version must be explicitly pinned before any lab scan',()=>{
  const e=safe();delete e.CYBER_HAK_STRIX_EXPECTED_VERSION;
  assert.throws(()=>assessRuntime(e,'--run'),/PINNED_STRIX_VERSION_REQUIRED/);
  e.CYBER_HAK_STRIX_EXPECTED_VERSION='latest';
  assert.throws(()=>assessRuntime(e,'--run'),/PINNED_STRIX_VERSION_REQUIRED/);
});

test('additional privileged environment credentials are refused',()=>{
  for(const name of ['GITHUB_ADMIN_TOKEN','SUPABASE_ACCESS_TOKEN',
    'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','GOOGLE_APPLICATION_CREDENTIALS',
    'STRIPE_SECRET_KEY']){
    const e=safe();e[name]='synthetic-test-secret-not-real';
    assert.throws(()=>assessRuntime(e,'--run'),
      /PRIVILEGED_OR_EXTERNAL_SECRET_ENV_DENIED/,name);
  }
});

test('Strix exit zero alone is not an authenticated vulnerability-free result',()=>{
  assert.equal(evaluated({exitCode:0,runStatus:'completed',
    findingsCount:0,evidencePresent:true}),'STRIX_REPORTED_NO_FINDINGS_QA_PENDING');
  assert.equal(evaluated({exitCode:0,runStatus:'stopped',
    findingsCount:0,evidencePresent:true}),'STRIX_INCOMPLETE_OR_STOPPED');
  assert.equal(evaluated({exitCode:0,runStatus:'completed',
    findingsCount:0,evidencePresent:false}),'STRIX_EVIDENCE_INCOMPLETE');
  assert.equal(evaluated({exitCode:0,runStatus:'completed',
    findingsCount:2,evidencePresent:true}),'STRIX_EXIT_AND_EVIDENCE_DISAGREE');
});

test('Strix findings remain blocked and require independent QA',()=>{
  assert.equal(evaluated({exitCode:2,runStatus:'completed',
    findingsCount:2,evidencePresent:true}),'STRIX_REPORTED_FINDINGS_QA_PENDING');
  assert.equal(evaluated({exitCode:1,runStatus:'completed',
    findingsCount:0,evidencePresent:true}),'STRIX_FATAL_ERROR');
  assert.equal(evaluated({exitCode:2,runStatus:'completed',
    findingsCount:0,evidencePresent:true}),'STRIX_EXIT_AND_EVIDENCE_DISAGREE');
  assert.equal(evaluated({exitCode:null,runStatus:'completed',
    findingsCount:0,evidencePresent:true}),'STRIX_PROCESS_UNVERIFIED');
});

test('staged source hash changes on artifact mutation',t=>{
  const root=mkdtempSync(join(tmpdir(),'imperial-strix-fingerprint-'));
  t.after(()=>rmSync(root,{force:true,recursive:true}));
  const file=join(root,'readme.txt');
  writeFileSync(file,'safe synthetic fixture');
  const first=sourceFingerprint(root);
  assert.equal(first.fileCount,1);
  assert.match(first.sha256,/^[0-9a-f]{64}$/);
  writeFileSync(file,'safe synthetic fixture changed');
  const second=sourceFingerprint(root);
  assert.notEqual(first.sha256,second.sha256);
});

test('source tree symlinks are denied before copying into Strix target',t=>{
  const root=mkdtempSync(join(tmpdir(),'imperial-strix-link-'));
  t.after(()=>rmSync(root,{force:true,recursive:true}));
  writeFileSync(join(root,'safe.txt'),'safe');
  symlinkSync(join(root,'safe.txt'),join(root,'unsafe.txt'));
  assert.throws(()=>sourceFingerprint(root),/SYMLINK_SOURCE_DENIED/);
});

test('incomplete Strix artifact directory cannot count as completed assessment',t=>{
  const root=mkdtempSync(join(tmpdir(),'imperial-strix-artifact-'));
  t.after(()=>rmSync(root,{force:true,recursive:true}));
  assert.equal(inspectStrixArtifacts(root,0).status,'STRIX_EVIDENCE_INCOMPLETE');
  const dir=join(root,'strix_runs','run-A');
  mkdirSync(dir,{recursive:true});
  writeFileSync(join(dir,'run.json'),JSON.stringify({
    status:'completed',end_time:'2026-11-01T11:30:00Z',llm_usage:{cost:0},
    targets_info:[{original:join(root,'public-source')}]
  }));
  assert.equal(inspectStrixArtifacts(root,0).status,'STRIX_EVIDENCE_INCOMPLETE');
  writeFileSync(join(dir,'vulnerabilities.json'),'[]');
  assert.equal(inspectStrixArtifacts(root,0).status,'STRIX_REPORTED_NO_FINDINGS_QA_PENDING');
  assert.equal(inspectStrixArtifacts(root,0).independentQA,false);
});

test('Strix early budget stop is incomplete regardless of zero tool exit',t=>{
  const root=mkdtempSync(join(tmpdir(),'imperial-strix-stopped-'));
  t.after(()=>rmSync(root,{force:true,recursive:true}));
  const dir=join(root,'strix_runs','run-B');mkdirSync(dir,{recursive:true});
  writeFileSync(join(dir,'run.json'),JSON.stringify({status:'stopped'}));
  writeFileSync(join(dir,'vulnerabilities.json'),'[]');
  assert.equal(inspectStrixArtifacts(root,0).status,'STRIX_INCOMPLETE_OR_STOPPED');
});


test('Strix exit 0 with no recorded end time is NOT a clean finding',()=>{
  assert.equal(evaluated({exitCode:0,runStatus:'completed',
    findingsCount:0,evidencePresent:true,endTime:null}),
    'STRIX_COMPLETION_NOT_ATTESTED');
});

test('Strix exit 0 against another target is not attributed to owned source',()=>{
  assert.equal(evaluated({exitCode:0,runStatus:'completed',
    findingsCount:0,evidencePresent:true,reportedTarget:'https://other.invalid'}),
    'STRIX_SCOPE_NOT_ATTESTED');
});

test('Strix missing usage or near budget cap denies clean claim',()=>{
  const record={exitCode:0,runStatus:'completed',
    findingsCount:0,evidencePresent:true};
  assert.equal(evaluated({...record,spentUsd:null}),'STRIX_BUDGET_NOT_ATTESTED');
  assert.equal(evaluated({...record,spentUsd:0.0095}),
    'STRIX_BUDGET_COVERAGE_UNVERIFIED');
});

test('Strix report JSON with missing target binding remains unverified',t=>{
  const root=mkdtempSync(join(tmpdir(),'imperial-strix-binding-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const dir=join(root,'strix_runs','run-C');mkdirSync(dir,{recursive:true});
  writeFileSync(join(dir,'run.json'),JSON.stringify({
    status:'completed',end_time:'2026-11-01T12:00:00Z',llm_usage:{cost:0},
    targets_info:[{original:'/other/target'}]
  }));
  writeFileSync(join(dir,'vulnerabilities.json'),'[]');
  const outcome=inspectStrixArtifacts(root,0);
  assert.equal(outcome.status,'STRIX_SCOPE_NOT_ATTESTED');
  assert.equal(outcome.targetMatches,false);
});

test('symlinked Strix result folder rejected before evidence parsing',t=>{
  const root=mkdtempSync(join(tmpdir(),'imperial-strix-result-link-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const external=mkdtempSync(join(tmpdir(),'imperial-strix-outside-'));
  t.after(()=>rmSync(external,{recursive:true,force:true}));
  symlinkSync(external,join(root,'strix_runs'),'dir');
  assert.throws(()=>inspectStrixArtifacts(root,0),
    /UNSAFE_STRIX_RUNS_DIRECTORY/);
});


test('signed owner permit path and independent trust root are required for live scanner mode',()=>{
 for(const key of ['CYBER_HAK_STRIX_SIGNED_PERMIT_PATH',
                   'CYBER_HAK_STRIX_OWNER_PUBLIC_KEY_PATH',
                   'CYBER_HAK_STRIX_NONCE_STORE']){
  const e=safe();delete e[key];
  assert.throws(()=>assessRuntime(e,'--run'),/OWNER_SIGNED_LAB_CONFIG_REQUIRED/);
 }
 const bad=safe();bad.CYBER_HAK_STRIX_OWNER_SPKI_SHA256='not_a_sha256';
 assert.throws(()=>assessRuntime(bad,'--run'),/OWNER_TRUST_ROOT_UNAVAILABLE/);
});

test('signed permit files cannot be replaced by relative paths',()=>{
 for(const key of ['CYBER_HAK_STRIX_SIGNED_PERMIT_PATH',
                   'CYBER_HAK_STRIX_OWNER_PUBLIC_KEY_PATH',
                   'CYBER_HAK_STRIX_NONCE_STORE']){
   const e=safe();e[key]='./some/relative/path';
   assert.throws(()=>assessRuntime(e,'--run'),/OWNER_SIGNED_LAB_CONFIG_REQUIRED/);
 }
});

test('synthetic owner env declarations alone still never count as an actual Strix run',()=>{
 const e=safe(),r=assessRuntime(e,'--run');
 assert.equal(r.status,'LOCAL_LAB_ADMISSIBLE_NOT_SCANNED');
 assert.equal(r.externalEffects,0);
});
