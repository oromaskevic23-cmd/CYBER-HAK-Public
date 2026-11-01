/**
 * CYBER HAK — immutable policy proposal for a single GitHub main-branch ruleset.
 * Pure configuration only. Nothing here uses credentials or the GitHub API.
 * Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
 */
export const OWNER='oromaskevic23-cmd';
export const RULESET_NAME='IMPERIAL Enterprise Main Branch Protection v1';
export const REQUIRED_GATE='enterprise-quality / enterprise-error-gate';

export function validateTarget(repo){
  if(typeof repo!=='string' ||
      !new RegExp('^'+OWNER+'/[A-Za-z0-9_.-]{1,100}$').test(repo) ||
      repo.includes('..') || repo.endsWith('.git'))
    throw Error('UNAUTHORIZED_REPOSITORY');
  return repo;
}

export function buildMainRuleset(repo,{extraChecks=[]}={}){
  validateTarget(repo);
  if(!Array.isArray(extraChecks)||extraChecks.length>8||
     extraChecks.some(x=>typeof x!=='string'||x.length<3||x.length>160||
       /[\r\n\u0000-\u001f]/.test(x)))throw Error('INVALID_CHECK');
  const checks=[REQUIRED_GATE,...extraChecks];
  if(new Set(checks).size!==checks.length)throw Error('DUPLICATE_CHECK');
  return {
    name:RULESET_NAME,
    target:'branch',
    enforcement:'active',
    bypass_actors:[],
    conditions:{ref_name:{include:['refs/heads/main'],exclude:[]}},
    rules:[
      {type:'deletion'},
      {type:'non_fast_forward'},
      {type:'pull_request',parameters:{
        allowed_merge_methods:['squash'],
        dismiss_stale_reviews_on_push:true,
        require_code_owner_review:false,
        require_last_push_approval:false,
        required_approving_review_count:0,
        required_review_thread_resolution:true
      }},
      {type:'required_status_checks',parameters:{
        do_not_enforce_on_create:false,
        required_status_checks:checks.map(context=>({context})),
        strict_required_status_checks_policy:true
      }}
    ]
  };
}

/** Verify actual GitHub API response; a proposal by itself is not enforcement. */
export function assertRulesetEnforced(actual,expected){
  if(!actual||actual.name!==RULESET_NAME||
     actual.enforcement!=='active'||actual.target!=='branch' ||
     !Array.isArray(actual.rules))throw Error('RULESET_NOT_ENFORCED');
  const refs=actual.conditions?.ref_name;
  if(!refs||!Array.isArray(refs.include)||refs.include.length!==1||
    refs.include[0]!=='refs/heads/main' ||
    !Array.isArray(refs.exclude)||refs.exclude.length!==0)
    throw Error('RULESET_TARGET_MISMATCH');
  if(actual.bypass_actors!==undefined&&
     (!Array.isArray(actual.bypass_actors)||actual.bypass_actors.length!==0))
    throw Error('UNEXPECTED_BYPASS_ACTOR');
  const types=actual.rules.map(x=>x.type);
  if(types.length!==expected.rules.length ||
     new Set(types).size!==types.length ||
     expected.rules.some(r=>!types.includes(r.type)))
    throw Error('RULESET_RULES_MISMATCH');
  for(const rule of expected.rules){
    const observed=actual.rules.find(x=>x.type===rule.type);
    if(rule.type==='required_status_checks'){
      if(observed.parameters?.strict_required_status_checks_policy!==true ||
         observed.parameters?.do_not_enforce_on_create!==false)
        throw Error('RULESET_CHECK_POLICY_MISMATCH');
      const got=observed.parameters?.required_status_checks?.map(x=>x.context);
      const want=rule.parameters.required_status_checks.map(x=>x.context);
      if(!Array.isArray(got)||got.length!==want.length||
         want.some(x=>!got.includes(x)))throw Error('RULESET_CHECKS_MISMATCH');
    }else if(rule.type==='pull_request'){
      const p=observed.parameters;
      if(!p||p.required_review_thread_resolution!==true ||
         p.required_approving_review_count!==0 ||
         !Array.isArray(p.allowed_merge_methods) ||
         !p.allowed_merge_methods.includes('squash'))
        throw Error('RULESET_PR_POLICY_MISMATCH');
    }
  }
  return true;
}
