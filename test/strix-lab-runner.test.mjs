import test from 'node:test';
import assert from 'node:assert/strict';
import {assessRuntime} from '../tools/strix-lab-runner.mjs';

const safe=()=>({
  CYBER_HAK_STRIX_LOCAL_RUN:'EXPLICITLY_APPROVED',
  CYBER_HAK_STRIX_ISOLATED_HOST:'CONFIRMED',
  STRIX_LLM:'ollama/qwen3-vl',
  LLM_API_BASE:'http://127.0.0.1:11434'
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
