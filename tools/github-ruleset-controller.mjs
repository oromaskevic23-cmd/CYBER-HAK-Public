#!/usr/bin/env node
/**
 * Owner-operated GitHub Rulesets enrollment. Dry-run by default.
 * --apply creates ONE ruleset in ONE repository after an explicit Owner
 * confirmation and a verified green Enterprise Gate on current main.
 * No CI use, no bulk application, no automatic changing existing rulesets.
 */
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildMainRuleset,assertRulesetEnforced,REQUIRED_GATE,
  RULESET_NAME,validateTarget} from '../security/rulesets/main-ruleset.mjs';

export function parseOptions(args){
  if(!Array.isArray(args)||args.length!==3||args[1]!=='--repo'||
     !['--plan','--apply'].includes(args[0]))
    throw Error('USAGE_PLAN_OR_APPLY_REPO_OWNER_NAME');
  return {mode:args[0],repo:validateTarget(args[2])};
}

export function assertGateReady(checkRuns,headSha){
  if(!Array.isArray(checkRuns)||checkRuns.length===0||checkRuns.length>100||
     typeof headSha!=='string'||!/^[0-9a-f]{40}$/i.test(headSha))
    throw Error('REQUIRED_CHECK_EVIDENCE_UNAVAILABLE');
  const gate=checkRuns.find(x=>x.name===REQUIRED_GATE &&
    x.head_sha===headSha && x.status==='completed' &&
    x.conclusion==='success');
  if(!gate)throw Error('REQUIRED_GATE_NOT_GREEN_ON_MAIN');
  return true;
}

export function assertOwnerExecution(env=process.env,stdin=process.stdin){
  if(env.CI||env.GITHUB_ACTIONS)throw Error('ADMIN_APPLY_FORBIDDEN_IN_CI');
  if(stdin?.isTTY!==true)throw Error('INTERACTIVE_OWNER_TERMINAL_REQUIRED');
  if(env.CYBER_HAK_RULESET_OWNER_APPROVAL!=='ACTIVATE_ONE_MAIN_RULESET')
    throw Error('OWNER_RULESET_CONFIRMATION_REQUIRED');
  if(typeof env.GH_ADMIN_TOKEN!=='string' || env.GH_ADMIN_TOKEN.length<20)
    throw Error('LOCAL_GITHUB_ADMIN_TOKEN_REQUIRED');
  return true;
}

async function api(repo,path,token,{method='GET',body,fetchImpl=fetch}={}){
  const url='https://api.github.com/repos/'+repo+path;
  const res=await fetchImpl(url,{
    method,redirect:'error',signal:AbortSignal.timeout(10000),
    headers:{
      Accept:'application/vnd.github+json',
      Authorization:'Bearer '+token,
      'X-GitHub-Api-Version':'2022-11-28',
      ...(method==='POST'?{'Content-Type':'application/json'}:{})
    },
    ...(method==='POST'?{body:JSON.stringify(body)}:{})
  });
  if(!res||!Number.isSafeInteger(res.status))throw Error('GITHUB_RESPONSE_INVALID');
  if(method==='POST'&&res.status!==201)
    throw Error('RULESET_CREATE_DENIED_HTTP_'+res.status);
  if(method==='GET'&&res.status!==200)
    throw Error('GITHUB_PREFLIGHT_DENIED_HTTP_'+res.status);
  const raw=await res.text();
  if(raw.length>500000)throw Error('GITHUB_RESPONSE_TOO_LARGE');
  try{return JSON.parse(raw);}catch{throw Error('GITHUB_RESPONSE_JSON_INVALID');}
}

export async function applyOneRuleset({repo,token,fetchImpl=fetch}){
  validateTarget(repo);
  const policy=buildMainRuleset(repo);
  const req=(path,options={})=>api(repo,path,token,{...options,fetchImpl});
  const data=await req('');
  if(data.full_name!==repo||data.default_branch!=='main'||data.archived===true)
    throw Error('UNEXPECTED_REPOSITORY_STATE');
  const existing=await req('/rulesets?includes_parents=false&per_page=100');
  if(!Array.isArray(existing)||existing.length>90)
    throw Error('EXISTING_RULESETS_UNREVIEWED');
  // No unexpected active existing protection is silently changed/overridden.
  if(existing.some(x=>x.name===RULESET_NAME))
    throw Error('RULESET_ALREADY_EXISTS_USE_READ_ONLY_VERIFICATION');
  if(existing.some(x=>x.enforcement==='active'))
    throw Error('EXISTING_ACTIVE_RULESET_NEEDS_MANUAL_REVIEW');
  const branch=await req('/branches/main');
  const headSha=branch?.commit?.sha;
  if(!/^[a-f0-9]{40}$/i.test(headSha||''))
    throw Error('MAIN_COMMIT_UNKNOWN');
  const checks=await req('/commits/'+headSha+'/check-runs?per_page=100');
  if(!checks||!Array.isArray(checks.check_runs)||
    checks.total_count>100)throw Error('CHECK_RUN_COVERAGE_INCOMPLETE');
  assertGateReady(checks.check_runs,headSha);
  const created=await req('/rulesets',{method:'POST',body:policy});
  if(!Number.isSafeInteger(created.id)||created.id<1)
    throw Error('RULESET_CREATED_BUT_ID_UNAVAILABLE_MANUAL_REVIEW');
  // Never print PASS based solely on an HTTP 201; read authoritative state.
  const installed=await req('/rulesets/'+created.id);
  assertRulesetEnforced(installed,policy);
  return {status:'ACTIVE_VERIFIED',repo,rulesetId:created.id,
    branch:'main',requiredCheck:REQUIRED_GATE,checkSha:headSha,
    bypassCount:0};
}

async function main(){
  const opts=parseOptions(process.argv.slice(2));
  const policy=buildMainRuleset(opts.repo);
  if(opts.mode==='--plan'){
    console.log(JSON.stringify({status:'PROPOSED_NOT_INSTALLED',
      repo:opts.repo,requires:'OWNER_ADMINISTRATION_WRITE_AND_GITHUB_PLAN',
      requiredCheck:REQUIRED_GATE,policy},null,2));
    return;
  }
  assertOwnerExecution();
  const result=await applyOneRuleset({
    repo:opts.repo,token:process.env.GH_ADMIN_TOKEN
  });
  console.log(JSON.stringify(result));
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  main().catch(e=>{
    console.error('CYBER_HAK_RULESET_DENIED:'+
      String(e?.message).replace(/[^A-Z0-9_]/g,'_'));
    process.exitCode=1;
  });
}
