import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildMainRuleset,assertRulesetEnforced,REQUIRED_GATE,
 validateTarget} from '../security/rulesets/main-ruleset.mjs';
import {parseOptions,assertGateReady,assertOwnerExecution,applyOneRuleset}
 from '../tools/github-ruleset-controller.mjs';

const repo='oromaskevic23-cmd/CYBER-HAK-Public';
const sha='a'.repeat(40);
const green={name:REQUIRED_GATE,head_sha:sha,status:'completed',conclusion:'success'};
const res=(data,status=200)=>({status,text:async()=>JSON.stringify(data)});

function fakeApi({missingGate=false,existing=[],createStatus=201,
 defaultBranch='main',wrongResult=false}={}){
 const calls=[],base='/repos/'+repo;
 const fetchImpl=async(url,opt)=>{
  const path=new URL(url).pathname;
  calls.push({path,method:opt.method,headers:opt.headers,body:opt.body});
  if(path===base)return res({full_name:repo,default_branch:defaultBranch,
    archived:false,private:false});
  if(path===base+'/rulesets'){
    if(opt.method==='POST')return res({...buildMainRuleset(repo),id:71},createStatus);
    return res(existing);
  }
  if(path===base+'/branches/main')return res({commit:{sha}});
  if(path===base+'/commits/'+sha+'/check-runs')
    return res({total_count:missingGate?0:1,check_runs:missingGate?[]:[green]});
  if(path===base+'/rulesets/71')
    return res(wrongResult?{id:71,enforcement:'disabled'}:
      {...buildMainRuleset(repo),id:71});
  throw Error('UNEXPECTED_MOCK_API');
 };
 return {fetchImpl,calls};
}

test('only repositories owned by the Architect are accepted',()=>{
 assert.equal(validateTarget(repo),repo);
 for(const n of ['outsider/repo','oromaskevic23-cmd/../../secret',
  'oromaskevic23-cmd/fake.git','oromaskevic23-cmd/f%2fo','invalid']){
  assert.throws(()=>validateTarget(n),/UNAUTHORIZED_REPOSITORY/);
 }
});

test('strict main ruleset requires verified check and no bypass',()=>{
 const p=buildMainRuleset(repo);
 assert.equal(p.enforcement,'active');
 assert.deepEqual(p.bypass_actors,[]);
 assert.deepEqual(p.conditions.ref_name.include,['refs/heads/main']);
 assert.deepEqual(p.rules.map(x=>x.type),[
  'deletion','non_fast_forward','pull_request','required_status_checks']);
 assert.deepEqual(p.rules.at(-1).parameters.required_status_checks,
  [{context:REQUIRED_GATE}]);
 assert.equal(p.rules.at(-1).parameters.strict_required_status_checks_policy,true);
 assert.equal(p.rules[2].parameters.required_approving_review_count,0);
 assert.deepEqual(p.rules[2].parameters.allowed_merge_methods,['squash']);
});

test('extra contexts are restricted, duplicates denied',()=>{
 assert.equal(buildMainRuleset(repo,{extraChecks:['offline-defensive-tests']})
  .rules.at(-1).parameters.required_status_checks.length,2);
 assert.throws(()=>buildMainRuleset(repo,{extraChecks:[REQUIRED_GATE]}),
  /DUPLICATE_CHECK/);
 assert.throws(()=>buildMainRuleset(repo,{extraChecks:['\nspoof']}),
  /INVALID_CHECK/);
});

test('plan mode is offline and never claims enforcement',()=>{
 assert.deepEqual(parseOptions(['--plan','--repo',repo]),{mode:'--plan',repo});
 assert.throws(()=>parseOptions(['--plan','--repo','foreign/name']),
  /UNAUTHORIZED_REPOSITORY/);
 const cli=resolve(fileURLToPath(new URL('../tools/github-ruleset-controller.mjs',
  import.meta.url)));
 const run=spawnSync(process.execPath,[cli,'--plan','--repo',repo],{
  env:{PATH:process.env.PATH},encoding:'utf8',timeout:10000
 });
 assert.equal(run.status,0);
 const plan=JSON.parse(run.stdout);
 assert.equal(plan.status,'PROPOSED_NOT_INSTALLED');
 assert(!run.stdout.includes('ghp_'));
});

test('apply requires real interactive confirmation and no CI environment',()=>{
 const env={GH_ADMIN_TOKEN:'a'.repeat(32)};
 assert.throws(()=>assertOwnerExecution(env,{isTTY:true}),
  /OWNER_RULESET_CONFIRMATION_REQUIRED/);
 env.CYBER_HAK_RULESET_OWNER_APPROVAL='ACTIVATE_ONE_MAIN_RULESET';
 assert.throws(()=>assertOwnerExecution(env,{isTTY:false}),
  /INTERACTIVE_OWNER_TERMINAL_REQUIRED/);
 env.CI='1';
 assert.throws(()=>assertOwnerExecution(env,{isTTY:true}),/ADMIN_APPLY_FORBIDDEN_IN_CI/);
 delete env.CI;delete env.GH_ADMIN_TOKEN;
 assert.throws(()=>assertOwnerExecution(env,{isTTY:true}),
  /LOCAL_GITHUB_ADMIN_TOKEN_REQUIRED/);
 env.GH_ADMIN_TOKEN='a'.repeat(32);
 assert.equal(assertOwnerExecution(env,{isTTY:true}),true);
});

test('a failing, stale or foreign check blocks enrollment',()=>{
 assert.equal(assertGateReady([green],sha),true);
 for(const f of [{...green,conclusion:'failure'},
   {...green,head_sha:'b'.repeat(40)},
   {...green,status:'in_progress'},{...green,name:'evil'}])
  assert.throws(()=>assertGateReady([f],sha),/REQUIRED_GATE_NOT_GREEN_ON_MAIN/);
});

test('mocked good API enrolls one ruleset, then independently verifies it',async()=>{
 const mock=fakeApi();
 const r=await applyOneRuleset({repo,token:'mock',fetchImpl:mock.fetchImpl});
 assert.equal(r.status,'ACTIVE_VERIFIED');
 assert.equal(r.rulesetId,71);
 assert.equal(mock.calls.filter(x=>x.method==='POST').length,1);
 const post=mock.calls.find(x=>x.method==='POST');
 assert.deepEqual(JSON.parse(post.body).bypass_actors,[]);
 assert(mock.calls.every(x=>x.headers.Authorization==='Bearer mock'));
});

test('missing required CI never writes to GitHub',async()=>{
 const mock=fakeApi({missingGate:true});
 await assert.rejects(applyOneRuleset({repo,token:'mock',
  fetchImpl:mock.fetchImpl}),/REQUIRED_CHECK_EVIDENCE_UNAVAILABLE/);
 assert.equal(mock.calls.filter(x=>x.method==='POST').length,0);
});

test('existing same-name or other active ruleset refuses silent layering',async()=>{
 for(const e of [[{name:buildMainRuleset(repo).name,enforcement:'active'}],
   [{name:'other',enforcement:'active'}]]){
  const mock=fakeApi({existing:e});
  await assert.rejects(applyOneRuleset({repo,token:'mock',
   fetchImpl:mock.fetchImpl}),/RULESET_ALREADY_EXISTS|EXISTING_ACTIVE_RULESET/);
  assert.equal(mock.calls.filter(x=>x.method==='POST').length,0);
 }
});

test('unexpected default branch cannot be targeted',async()=>{
 const mock=fakeApi({defaultBranch:'release'});
 await assert.rejects(applyOneRuleset({repo,token:'mock',
  fetchImpl:mock.fetchImpl}),/UNEXPECTED_REPOSITORY_STATE/);
 assert.equal(mock.calls.filter(x=>x.method==='POST').length,0);
});

test('GitHub API 403 and 422 errors deny without leaking authentication',async()=>{
 const denied=async(_url,options)=>{
  assert.equal(options.headers.Authorization,'Bearer top-secret-test');
  return res({message:'denied'},403);
 };
 await assert.rejects(applyOneRuleset({repo,token:'top-secret-test',
  fetchImpl:denied}),e=>e.message==='GITHUB_PREFLIGHT_DENIED_HTTP_403');
 const mock=fakeApi({createStatus:422});
 await assert.rejects(applyOneRuleset({repo,token:'mock',
  fetchImpl:mock.fetchImpl}),/RULESET_CREATE_DENIED_HTTP_422/);
});

test('GitHub 201 without verified active readback must not claim success',async()=>{
 const mock=fakeApi({wrongResult:true});
 await assert.rejects(applyOneRuleset({repo,token:'mock',
  fetchImpl:mock.fetchImpl}),/RULESET_NOT_ENFORCED/);
});

test('readback validation denies bypass, wrong check and wrong branch',()=>{
 const p=buildMainRuleset(repo);
 assert.equal(assertRulesetEnforced(p,p),true);
 assert.throws(()=>assertRulesetEnforced({...p,enforcement:'disabled'},p),
  /RULESET_NOT_ENFORCED/);
 assert.throws(()=>assertRulesetEnforced({...p,bypass_actors:[{actor_id:1}]},p),
  /UNEXPECTED_BYPASS_ACTOR/);
 assert.throws(()=>assertRulesetEnforced({...p,conditions:{ref_name:{
  include:['refs/heads/dev'],exclude:[]}}},p),/RULESET_TARGET_MISMATCH/);
 const c=structuredClone(p);
 c.rules.at(-1).parameters.required_status_checks=[{context:'wrong'}];
 assert.throws(()=>assertRulesetEnforced(c,p),/RULESET_CHECKS_MISMATCH/);
});
