/**
 * CYBER HAK — ORION Guardian Review Gate v0.1.
 * Independently checks exact signed advisory claims against a readonly ORION
 * report and pinned Ed25519 public keys. Does not approve tasks or releases.
 * PUBLIC defensive reference; no remote calls, filesystem access or signer.
 */
import {createHash,createPublicKey,KeyObject,verify} from 'node:crypto';
const SHA=/^[a-f0-9]{64}$/,NONCE=/^[a-f0-9]{32,64}$/;
const MISSION=/^MISSION-[A-Z0-9_-]{6,48}$/;
const DOMAIN=/^DOMAIN-[A-Z0-9_-]{3,40}$/;
const AGENT=/^NCA-[0-9]{12,13}$/;
const CLAIM=/^CLAIM-[A-Z0-9_-]{3,60}$/;
const KEYS=['schema','mission_id','domain_id','agent_id','claim_id','stance',
 'evidence_sha256','summary','issued_at','expires_at','nonce'];
const REPORT_KEYS=['schema','mission_id','report_status','claims',
 'human_review_required','truth_verified','execution','task_dispatch','approval',
 'release','persistence','global_orchestrator','report_sha256','audit_last_sha256'];
const CLAIM_KEYS=['claim_id','status','independent_domain_count',
 'evidence_reference_count','evidence_verified','domain_positions','review_question'];
const POSITION_KEYS=['domain_id','agent_id','stance','summary_sha256',
 'payload_sha256','evidence_sha256'];
const HASH=x=>createHash('sha256').update(x).digest('hex');
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>own(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const gate=(ok,code)=>{if(!ok)throw new Error(code);};
const stamp=(fields,object)=>JSON.stringify(Object.fromEntries(fields.map(k=>[k,object[k]])));
function parsedKey(x){
 try{
  gate((x instanceof KeyObject&&x.type==='public')||
   (typeof x==='string'&&x.startsWith('-----BEGIN PUBLIC KEY-----')),
    'ORION_GUARD_TRUST_ANCHOR_INVALID');
  const k=x instanceof KeyObject?x:createPublicKey(x);
  gate(k.type==='public'&&k.asymmetricKeyType==='ed25519',
   'ORION_GUARD_TRUST_ANCHOR_INVALID');
  return k;
 }catch{throw new Error('ORION_GUARD_TRUST_ANCHOR_INVALID');}
}
function validClaim(c,missionId,now){
 gate(exact(c,KEYS)&&c.schema==='imperial_orion_advisory_v1'&&
  c.mission_id===missionId&&MISSION.test(c.mission_id)&&
  DOMAIN.test(c.domain_id)&&AGENT.test(c.agent_id)&&CLAIM.test(c.claim_id)&&
  ['FOR','AGAINST','UNSURE'].includes(c.stance)&&
  Array.isArray(c.evidence_sha256)&&c.evidence_sha256.length>=1&&
  c.evidence_sha256.length<=5&&c.evidence_sha256.every(x=>typeof x==='string'&&SHA.test(x))&&
  new Set(c.evidence_sha256).size===c.evidence_sha256.length&&
  typeof c.summary==='string'&&c.summary.length>=1&&c.summary.length<=800&&
  !/[\u0000-\u001f\u007f]/.test(c.summary)&&
  typeof c.nonce==='string'&&NONCE.test(c.nonce)&&
  Number.isSafeInteger(c.issued_at)&&Number.isSafeInteger(c.expires_at)&&
  c.issued_at>=0&&c.issued_at<=now+30000&&c.issued_at<=now&&
  c.expires_at>now&&c.expires_at-c.issued_at<=300000,
  'ORION_GUARD_CLAIM_INVALID');
}
function checkReport(r,missionId){
 gate(exact(r,REPORT_KEYS)&&r.schema==='imperial_orion_advisory_report_v1'&&
  r.mission_id===missionId&&r.report_status==='ADVISORY_ONLY'&&
  r.human_review_required===true&&r.truth_verified===false&&
  r.execution==='DENIED'&&r.task_dispatch==='DENIED'&&
  r.approval==='NOT_GRANTED'&&r.release==='DENIED'&&
  r.persistence==='IN_MEMORY_ONLY'&&r.global_orchestrator===false&&
  Array.isArray(r.claims)&&r.claims.length>=1&&r.claims.length<=64&&
  SHA.test(r.report_sha256)&&SHA.test(r.audit_last_sha256),
  'ORION_GUARD_REPORT_BOUNDARY_DENIED');
 const fields=REPORT_KEYS.filter(x=>x!=='report_sha256'&&x!=='audit_last_sha256');
 gate(HASH(stamp(fields,r))===r.report_sha256,'ORION_GUARD_REPORT_HASH_MISMATCH');
}
/** Produces ONLY a review or denial status and redacted hashes.
 * The caller must supply a pre-authorized trust registry; no key enrollment here.
 */
export function inspectSignedOrionReport({report,envelopes,trustedDomainPublicKeys,
 expectedMissionId,now=Date.now(),ownerHalted}={}){
 const reject=(reason)=>Object.freeze({
  schema:'cyber_hak_orion_guard_v1',decision:'DENY',reason,
  mission_id:MISSION.test(expectedMissionId??'')?expectedMissionId:null,
  execution:'DENIED',approval:'NOT_GRANTED',release:'DENIED',
  trust:'NOT_ESTABLISHED',runtime:'OFFLINE_REFERENCE',guardian_core:'NOT_DEPLOYED'
 });
 try{
  gate(ownerHalted===false,'ORION_GUARD_OWNER_HALTED');
  gate(MISSION.test(expectedMissionId??'')&&Number.isSafeInteger(now)&&now>=0,
   'ORION_GUARD_CONTEXT_INVALID');
  gate(Array.isArray(envelopes)&&envelopes.length>=2&&envelopes.length<=32&&
   Array.isArray(trustedDomainPublicKeys)&&trustedDomainPublicKeys.length===envelopes.length,
   'ORION_GUARD_INPUT_COUNT_DENIED');
  const trusted=new Map(),keys=new Set();
  for(const item of trustedDomainPublicKeys){
   gate(exact(item,['domain_id','public_key'])&&DOMAIN.test(item.domain_id)&&
    !trusted.has(item.domain_id),'ORION_GUARD_TRUST_REGISTRY_INVALID');
   const key=parsedKey(item.public_key);
   const fingerprint=HASH(key.export({type:'spki',format:'der'}));
   gate(!keys.has(fingerprint),'ORION_GUARD_DUPLICATE_DOMAIN_KEY');
   keys.add(fingerprint);trusted.set(item.domain_id,key);
  }
  checkReport(report,expectedMissionId);
  const claims=new Map(),nonces=new Set(),agents=new Set(),pairs=new Set();
  for(const envelope of envelopes){
   gate(exact(envelope,['claims','signature']),'ORION_GUARD_ENVELOPE_DENIED');
   const c=envelope.claims;validClaim(c,expectedMissionId,now);
   gate(trusted.has(c.domain_id)&&!nonces.has(c.domain_id+':'+c.nonce),
    'ORION_GUARD_DOMAIN_OR_REPLAY_DENIED');
   gate(!agents.has(c.agent_id)&&!pairs.has(c.domain_id+':'+c.claim_id),
    'ORION_GUARD_AGENT_OR_CLAIM_DUPLICATE');
   gate(typeof envelope.signature==='string'&&
    /^[A-Za-z0-9_-]{86}$/.test(envelope.signature),
    'ORION_GUARD_SIGNATURE_DENIED');
   const canonical=Buffer.from(stamp(KEYS,c));
   let verified=false;
   try{verified=verify(null,canonical,trusted.get(c.domain_id),
    Buffer.from(envelope.signature,'base64url'));}catch{}
   gate(verified,'ORION_GUARD_SIGNATURE_DENIED');
   nonces.add(c.domain_id+':'+c.nonce);agents.add(c.agent_id);
   pairs.add(c.domain_id+':'+c.claim_id);
   const id=c.claim_id+':'+c.domain_id;
   claims.set(id,{claim_id:c.claim_id,domain_id:c.domain_id,
    agent_id:c.agent_id,stance:c.stance,evidence_sha256:c.evidence_sha256,
    summary_sha256:HASH(c.summary),payload_sha256:HASH(canonical)});
  }
  let count=0,prevClaim='';
  for(const r of report.claims){
   gate(exact(r,CLAIM_KEYS)&&CLAIM.test(r.claim_id)&&r.claim_id>prevClaim&&
    r.evidence_verified===false&&Array.isArray(r.domain_positions)&&
    r.domain_positions.length>=1&&r.domain_positions.length<=32,
    'ORION_GUARD_REPORT_CLAIM_DENIED');
   prevClaim=r.claim_id;
   const stances=new Set(),domains=new Set(),groupAgents=new Set();
   let previousDomain='',refCount=0;
   for(const p of r.domain_positions){
    gate(exact(p,POSITION_KEYS)&&DOMAIN.test(p.domain_id)&&
     p.domain_id>previousDomain&&AGENT.test(p.agent_id)&&
     ['FOR','AGAINST','UNSURE'].includes(p.stance)&&
     Array.isArray(p.evidence_sha256),'ORION_GUARD_REPORT_POSITION_DENIED');
    previousDomain=p.domain_id;stances.add(p.stance);
    domains.add(p.domain_id);groupAgents.add(p.agent_id);
    const source=claims.get(r.claim_id+':'+p.domain_id);
    gate(source&&source.agent_id===p.agent_id&&source.stance===p.stance&&
     source.summary_sha256===p.summary_sha256&&
     source.payload_sha256===p.payload_sha256&&
     JSON.stringify(source.evidence_sha256)===JSON.stringify(p.evidence_sha256),
     'ORION_GUARD_SOURCE_OR_DIGEST_MISMATCH');
    claims.delete(r.claim_id+':'+p.domain_id);
    refCount+=p.evidence_sha256.length;count++;
   }
   gate(groupAgents.size===domains.size&&
    r.independent_domain_count===domains.size&&
    r.evidence_reference_count===refCount,
    'ORION_GUARD_REPORT_COUNTS_DRIFT');
   const contradiction=stances.has('FOR')&&stances.has('AGAINST');
   const label=contradiction?'CONTRADICTION_NEEDS_REVIEW':
     domains.size<2?'INSUFFICIENT_INDEPENDENT_DOMAINS':'UNCONTESTED_SIGNED_SUBMISSIONS';
   gate(r.status===label&&typeof r.review_question==='string'&&
    r.review_question.length>0,'ORION_GUARD_CONTRADICTION_DRIFT');
  }
  gate(count===envelopes.length&&claims.size===0,'ORION_GUARD_COVERAGE_MISMATCH');
  return Object.freeze({
   schema:'cyber_hak_orion_guard_v1',decision:'HUMAN_REVIEW_REQUIRED',
   reason:report.claims.some(c=>c.status==='CONTRADICTION_NEEDS_REVIEW')?
    'SIGNED_DISAGREEMENT_REVIEW':'SIGNED_EVIDENCE_REVIEW',
   mission_id:expectedMissionId,report_sha256:report.report_sha256,
   signed_advisories_checked:count,trust:'PINNED_KEYS_REFERENCE_ONLY',
   evidence_truth_verified:false,source_authority:'NOT_VERIFIED',
   execution:'DENIED',approval:'NOT_GRANTED',release:'DENIED',
   runtime:'OFFLINE_REFERENCE',guardian_core:'NOT_DEPLOYED'
  });
 }catch(e){return reject(e?.message?.startsWith('ORION_GUARD_')?
  e.message:'ORION_GUARD_UNEXPECTED_DENIAL');}
}
