import test from 'node:test';
import assert from 'node:assert/strict';
import {
  inspectMainRuleset
} from '../tools/github-ruleset-readback.mjs';
import {
  buildMainRuleset,RULESET_NAME,REQUIRED_GATE
} from '../security/rulesets/main-ruleset.mjs';

const repo='oromaskevic23-cmd/CYBER-HAK-Public';
const record={id:42,name:RULESET_NAME};
const response=(status,data)=>({
  status,headers:{get:()=>null},text:async()=>JSON.stringify(data)
});
function mock({list=[record],detail={...buildMainRuleset(repo),id:42},
  listStatus=200,detailStatus=200}={}){
  const requests=[];
  const fetchImpl=async(url,opts)=>{
    requests.push({url,opts});
    if(url.includes('/rulesets?'))return response(listStatus,list);
    if(url.endsWith('/rulesets/42'))return response(detailStatus,detail);
    throw Error('UNEXPECTED_EXTERNAL_REQUEST');
  };
  return {fetchImpl,requests};
}

test('missing ruleset does not claim mandatory branch protection',async()=>{
 const net=mock({list:[]});
 const result=await inspectMainRuleset({repo,fetchImpl:net.fetchImpl});
 assert.equal(result.status,'NO_MATCHING_RULESET_FOUND');
 assert.equal(result.policyConfigured,false);
 assert.equal(result.actualMergeDenialTested,false);
 assert.equal(result.externalEffects,0);
 assert.equal(net.requests.length,1);
});

test('verified active main ruleset is configuration evidence, not merge-denial evidence',async()=>{
 const net=mock();
 const result=await inspectMainRuleset({repo,fetchImpl:net.fetchImpl});
 assert.equal(result.status,'ACTIVE_RULESET_CONFIGURATION_VERIFIED');
 assert.equal(result.policyConfigured,true);
 assert.equal(result.rulesetId,42);
 assert.equal(result.actualMergeDenialTested,false);
 assert.equal(net.requests.length,2);
 assert(net.requests.every(x=>x.opts.method==='GET'));
 assert(net.requests.every(x=>x.opts.redirect==='error'));
});

test('403 access denied is not treated as an empty ruleset list',async()=>{
 const net=mock({listStatus:403});
 const result=await inspectMainRuleset({repo,fetchImpl:net.fetchImpl});
 assert.equal(result.status,'ACCESS_DENIED');
 assert.equal(result.policyConfigured,false);
 assert.equal(net.requests.length,1);
});

test('404 and unstable GitHub response remain unverified',async()=>{
 for(const status of [404,500,503]){
  const net=mock({listStatus:status});
  const result=await inspectMainRuleset({repo,fetchImpl:net.fetchImpl});
  assert.equal(result.policyConfigured,false);
 }
 const result=await inspectMainRuleset({repo,
   fetchImpl:async()=>{throw Error('OFFLINE');}});
 assert.equal(result.status,'UNAVAILABLE');
});

test('disabled ruleset and wrong required check both fail readback',async()=>{
 const wrong=structuredClone(buildMainRuleset(repo));
 wrong.rules.at(-1).parameters.required_status_checks=[{context:'fake-green'}];
 for(const detail of [
  {...buildMainRuleset(repo),enforcement:'disabled'},
  wrong
 ]){
  const net=mock({detail});
  const result=await inspectMainRuleset({repo,fetchImpl:net.fetchImpl});
  assert.equal(result.status,'RULESET_POLICY_MISMATCH');
  assert.equal(result.policyConfigured,false);
 }
});

test('ambiguity and unverified pagination refuse security attestation',async()=>{
 const duplicate=mock({list:[record,record]});
 const one=await inspectMainRuleset({repo,fetchImpl:duplicate.fetchImpl});
 assert.equal(one.status,'AMBIGUOUS_RULESETS');
 const many=mock({list:Array.from({length:100},(_,i)=>({id:i+1,name:'other'}))});
 const two=await inspectMainRuleset({repo,fetchImpl:many.fetchImpl});
 assert.equal(two.status,'PAGINATION_UNVERIFIED');
});

test('invalid owner repository target fails before any network operation',async()=>{
 let called=false;
 const fetchImpl=async()=>{called=true;throw Error('NO');};
 await assert.rejects(inspectMainRuleset({repo:'other-owner/private',fetchImpl}),
   /UNAUTHORIZED_REPOSITORY/);
 assert.equal(called,false);
});

test('optional read token stays in HTTP header, not receipt',async()=>{
 const token='test-only-token-'+'x'.repeat(20);
 const net=mock();
 const r=await inspectMainRuleset({repo,token,fetchImpl:net.fetchImpl});
 assert.equal(r.policyConfigured,true);
 assert(net.requests.every(x=>x.opts.headers.Authorization==='Bearer '+token));
 assert(!JSON.stringify(r).includes(token));
 assert.equal(net.requests[0].opts.headers.Accept,'application/vnd.github+json');
});

test('untrusted 200 response with wrong body shape cannot imply rules exist',async()=>{
 const net=mock({list:{message:'not allowed'}});
 const r=await inspectMainRuleset({repo,fetchImpl:net.fetchImpl});
 assert.equal(r.status,'INVALID_RESPONSE');
 assert.equal(r.policyConfigured,false);
});

test('missing required gate in claimed status check set is rejected',async()=>{
 const policy=buildMainRuleset(repo);
 assert.equal(policy.rules.at(-1).parameters.required_status_checks[0].context,REQUIRED_GATE);
 const truncated=structuredClone(policy);
 truncated.rules.at(-1).parameters.required_status_checks=[];
 const net=mock({detail:truncated});
 const r=await inspectMainRuleset({repo,fetchImpl:net.fetchImpl});
 assert.equal(r.status,'RULESET_POLICY_MISMATCH');
});
