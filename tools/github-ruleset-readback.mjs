#!/usr/bin/env node
/**
 * CYBER HAK / GitHub Main-Branch Ruleset — READ-ONLY evidence inspector.
 *
 * No administrator token required to inspect public rulesets. For private
 * repositories an authorized optional read token may be supplied locally.
 * Does not create, edit, delete or claim to bypass any protection.
 * Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
 */
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  validateTarget,buildMainRuleset,assertRulesetEnforced,RULESET_NAME
} from '../security/rulesets/main-ruleset.mjs';

const MAX_RESPONSE=512000;
function result(repo,status,details={}){
  return Object.freeze({schema:'cyber-hak.github.ruleset-inspection.v1',
    repo,status,policyConfigured:status==='ACTIVE_RULESET_CONFIGURATION_VERIFIED',
    actualMergeDenialTested:false,externalEffects:0,...details});
}
async function readJson(url,{token,fetchImpl}){
  let response;
  try{
    response=await fetchImpl(url,{method:'GET',redirect:'error',
      signal:AbortSignal.timeout(10000),
      headers:{
        Accept:'application/vnd.github+json',
        'X-GitHub-Api-Version':'2022-11-28',
        ...(token?{Authorization:'Bearer '+token}:{})
      }});
  }catch{
    return {kind:'UNAVAILABLE'};
  }
  if(!response||!Number.isSafeInteger(response.status))
    return {kind:'UNAVAILABLE'};
  if(response.status===401||response.status===403)
    return {kind:'ACCESS_DENIED'};
  if(response.status===404)
    return {kind:'NOT_FOUND_OR_INACCESSIBLE'};
  if(response.status!==200)
    return {kind:'HTTP_UNVERIFIED'};
  const length=response.headers?.get?.('content-length');
  if(length!==null&&length!==undefined&&
    (!/^\d+$/.test(length)||Number(length)>MAX_RESPONSE))
    return {kind:'INCOMPLETE_RESPONSE'};
  let raw;
  try{raw=await response.text();}catch{return {kind:'INCOMPLETE_RESPONSE'};}
  if(raw.length>MAX_RESPONSE)return {kind:'INCOMPLETE_RESPONSE'};
  try{return {kind:'OK',data:JSON.parse(raw)};}
  catch{return {kind:'INVALID_RESPONSE'};}
}

/**
 * Inspection result is deliberately weaker than proving GitHub rejected a
 * failing PR. No configured rule may be inferred from an HTTP 403/404.
 */
export async function inspectMainRuleset({
  repo,token=null,fetchImpl=fetch
}={}){
  validateTarget(repo);
  if(token!==null&&(typeof token!=='string'||token.length<10||
       token.length>10000))throw Error('READ_TOKEN_INVALID');
  if(typeof fetchImpl!=='function')throw Error('FETCH_IMPLEMENTATION_REQUIRED');
  const base='https://api.github.com/repos/'+repo;
  const list=await readJson(base+'/rulesets?includes_parents=false&per_page=100',
    {token,fetchImpl});
  if(list.kind!=='OK')return result(repo,list.kind);
  if(!Array.isArray(list.data))return result(repo,'INVALID_RESPONSE');
  // Do not assert that we saw every rule when GitHub may paginate after 100.
  if(list.data.length>=100)return result(repo,'PAGINATION_UNVERIFIED');
  const candidates=list.data.filter(x=>x?.name===RULESET_NAME);
  if(candidates.length===0)
    return result(repo,'NO_MATCHING_RULESET_FOUND');
  if(candidates.length!==1)
    return result(repo,'AMBIGUOUS_RULESETS');
  const id=candidates[0].id;
  if(!Number.isSafeInteger(id)||id<1)return result(repo,'RULESET_ID_INVALID');
  const detail=await readJson(base+'/rulesets/'+id,{token,fetchImpl});
  if(detail.kind!=='OK')return result(repo,detail.kind);
  try{
    assertRulesetEnforced(detail.data,buildMainRuleset(repo));
  }catch{
    return result(repo,'RULESET_POLICY_MISMATCH',{rulesetId:id});
  }
  return result(repo,'ACTIVE_RULESET_CONFIGURATION_VERIFIED',{rulesetId:id});
}

function parseArgs(args){
  if(args.length!==2||args[0]!=='--repo')
    throw Error('USAGE_READ_ONLY_REPO_OWNER_NAME');
  return validateTarget(args[1]);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const repo=parseArgs(process.argv.slice(2));
    const receipt=await inspectMainRuleset({
      repo,token:process.env.GH_RULESET_READ_TOKEN||null});
    console.log(JSON.stringify(receipt,null,2));
    if(!receipt.policyConfigured)process.exitCode=2;
  }catch(e){
    console.error('CYBER_HAK_RULESET_READ_DENIED:'+
      String(e?.message||'UNKNOWN').replace(/[^A-Z0-9_]/g,'_'));
    process.exitCode=1;
  }
}
