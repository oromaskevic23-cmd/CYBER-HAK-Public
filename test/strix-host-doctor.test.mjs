import test from 'node:test';
import assert from 'node:assert/strict';
import {doctor} from '../tools/strix-host-doctor.mjs';

const env=()=>({
  PATH:'/opt/test/bin',
  STRIX_LLM:'ollama/qwen3-vl',
  CYBER_HAK_STRIX_EXPECTED_VERSION:'1.2.3'
});
const healthy=(calls=[])=>((command,args,options)=>{
  calls.push({command,args,options});
  return {status:0,stdout:command==='ollama'&&args[0]==='list'?
    'NAME ID SIZE MODIFIED\nqwen3-vl:latest abc 4 GB now\n':'strix v1.2.3\n'};
});

test('available local tools never count as a Strix scan or verified host isolation',()=>{
  const calls=[],result=doctor({env:env(),run:healthy(calls)});
  assert.equal(result.status,'LOCAL_COMPONENTS_REACHABLE_ISOLATION_UNVERIFIED');
  assert.equal(result.localModelPresent,true);
  assert.equal(result.versionPinConfigured,true);
  assert.equal(result.realStrixScanExecuted,false);
  assert.equal(result.hostEgressIsolation,'UNVERIFIED');
  assert.equal(result.externalNetworkCalls,0);
  assert(calls.every(x=>['docker','strix','ollama'].includes(x.command)));
  assert(calls.every(x=>Object.keys(x.options.env).join('|')==='PATH'));
});

test('missing Docker blocks the lab instead of reporting readiness',()=>{
  const run=(cmd,args,opt)=>cmd==='docker'?{status:127,error:'ENOENT'}:
    healthy()(cmd,args,opt);
  const r=doctor({env:env(),run});
  assert.equal(r.status,'STRIX_LAB_HOST_BLOCKED');
  assert.equal(r.diagnostics[0].state,'UNAVAILABLE');
});

test('missing local model blocks even if Strix and Docker are present',()=>{
  const run=(cmd,args,opt)=>{
    if(cmd==='ollama'&&args[0]==='list')
      return {status:0,stdout:'NAME ID SIZE MODIFIED\nanother:latest abc 1GB now\n'};
    return healthy()(cmd,args,opt);
  };
  const r=doctor({env:env(),run});
  assert.equal(r.status,'STRIX_LAB_HOST_BLOCKED');
  assert.equal(r.localModelPresent,false);
});

test('unreviewed Strix version prevents readiness claim',()=>{
  const e=env();delete e.CYBER_HAK_STRIX_EXPECTED_VERSION;
  const r=doctor({env:e,run:healthy()});
  assert.equal(r.status,'STRIX_LAB_HOST_BLOCKED');
  assert.equal(r.versionPinConfigured,false);
});

test('cloud LLM not interpreted as local even with all binary checks passing',()=>{
  const e=env();e.STRIX_LLM='openai/external';
  const r=doctor({env:e,run:healthy()});
  assert.equal(r.localModelPresent,false);
  assert.equal(r.status,'STRIX_LAB_HOST_BLOCKED');
});

test('remote Docker socket is never accepted by offline doctor',()=>{
  const e=env();e.DOCKER_HOST='tcp://remote.example.invalid:2375';
  assert.throws(()=>doctor({env:e,run:healthy()}),/REMOTE_DOCKER_HOST_DENIED/);
});

test('secret-bearing environment denies before launching any child process',()=>{
  const calls=[],e=env();e.GITHUB_TOKEN='synthetic-fixture';
  assert.throws(()=>doctor({env:e,run:healthy(calls)}),
    /SECRET_BEARING_HOST_ENV_DENIED/);
  assert.equal(calls.length,0);
});

test('doctor never attempts network or Docker pull regardless of runner result',()=>{
  const calls=[];const r=doctor({env:env(),run:healthy(calls)});
  assert.equal(r.externalNetworkCalls,0);
  assert(!calls.some(x=>x.args.includes('pull')||x.command==='curl'));
});
