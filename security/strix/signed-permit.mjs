/**
 * CYBER HAK × Strix — offline Ed25519 signed lab-scope admission reference.
 *
 * The Owner PUBLIC key must be independently pinned outside the scan target;
 * the private key never enters GitHub, this process, or the Strix sandbox.
 * This verifier does NOT enroll an Owner key or prove lab egress isolation.
 * Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {lstatSync,mkdirSync,writeFileSync} from 'node:fs';
import {resolve,join,isAbsolute} from 'node:path';

const digest=x=>createHash('sha256').update(x).digest('hex');
const HEX=/^[a-f0-9]{64}$/;
const NONCE=/^[A-Za-z0-9_-]{16,80}$/;
const FIELD_ORDER=Object.freeze([
  'schema','missionId','targetSha256','scopeSha256','model','strixVersion',
  'nonce','issuedAt','expiresAt','productionAuthorized',
  'externalTargetsAuthorized','maxBudgetUsd'
]);
export const SIGN_DOMAIN='CYBER_HAK_STRIX_LAB_AUTH_V1\n';
export const MAX_PERMIT_TTL_MS=300_000;

export function permitSigningBytes(payload){
  if(!payload||typeof payload!=='object'||Array.isArray(payload)||
    Object.keys(payload).length!==FIELD_ORDER.length||
    FIELD_ORDER.some(key=>!Object.hasOwn(payload,key)))
    throw Error('PERMIT_SCHEMA_DENIED');
  // Fixed-order canonical serialization; do not sign object insertion order.
  return Buffer.from(SIGN_DOMAIN+JSON.stringify(
    Object.fromEntries(FIELD_ORDER.map(k=>[k,payload[k]]))),'utf8');
}

export function verifySignedLabPermit({
  permit,ownerPublicKeyPem,trustedOwnerSpkiSha256,
  expectedTargetSha256,expectedScopeSha256,
  expectedModel,expectedVersion,expectedBudgetUsd='0.01',
  now=Date.now()
}={}){
  if(typeof ownerPublicKeyPem!=='string'||ownerPublicKeyPem.length>8192||
     typeof trustedOwnerSpkiSha256!=='string'||!HEX.test(trustedOwnerSpkiSha256))
    throw Error('OWNER_TRUST_ROOT_UNAVAILABLE');
  if(typeof permit!=='object'||permit===null||Array.isArray(permit)||
    Object.keys(permit).length!==2||
    !Object.hasOwn(permit,'payload')||!Object.hasOwn(permit,'signature'))
    throw Error('SIGNED_LAB_PERMIT_REQUIRED');
  let key;
  try{key=createPublicKey(ownerPublicKeyPem)}catch{
    throw Error('OWNER_PUBLIC_KEY_INVALID');
  }
  if(key.asymmetricKeyType!=='ed25519')throw Error('OWNER_ED25519_REQUIRED');
  const spki=key.export({format:'der',type:'spki'});
  if(digest(spki)!==trustedOwnerSpkiSha256)
    throw Error('UNTRUSTED_OWNER_PUBLIC_KEY');
  const p=permit.payload,bytes=permitSigningBytes(p);
  if(p.schema!=='cyber-hak.strix.owner-lab-permit.v1'||
     typeof p.missionId!=='string'||
     !/^IC-STRIX-[A-Z0-9-]{8,80}$/.test(p.missionId)||
     !HEX.test(p.targetSha256)||!HEX.test(p.scopeSha256)||
     !NONCE.test(p.nonce)||
     p.productionAuthorized!==false||
     p.externalTargetsAuthorized!==false||
     typeof p.model!=='string'||p.model.length>120||
     typeof p.strixVersion!=='string'||p.strixVersion.length>100||
     typeof p.maxBudgetUsd!=='string'||
     !Number.isSafeInteger(p.issuedAt)||!Number.isSafeInteger(p.expiresAt)||
     !Number.isSafeInteger(now)||
     p.issuedAt>now+5000||p.expiresAt<=now||
     p.expiresAt<=p.issuedAt||
     p.expiresAt-p.issuedAt>MAX_PERMIT_TTL_MS)
    throw Error('PERMIT_SCOPE_OR_TTL_DENIED');
  if(p.targetSha256!==expectedTargetSha256||
     p.scopeSha256!==expectedScopeSha256||
     p.model!==expectedModel||p.strixVersion!==expectedVersion||
     p.maxBudgetUsd!==expectedBudgetUsd)
    throw Error('LAB_SCOPE_BINDING_MISMATCH');
  const sig=permit.signature;
  if(typeof sig!=='string'||sig.length>200||
     !/^[A-Za-z0-9_-]+$/.test(sig))
    throw Error('PERMIT_SIGNATURE_INVALID');
  const decoded=Buffer.from(sig,'base64url');
  if(decoded.length!==64||decoded.toString('base64url')!==sig)
    throw Error('PERMIT_SIGNATURE_INVALID');
  if(!verifySignature(null,bytes,key,decoded))
    throw Error('PERMIT_SIGNATURE_REJECTED');
  return Object.freeze({status:'OWNER_KEY_SIGNATURE_VERIFIED_FOR_LOCAL_LAB_ONLY',
    missionId:p.missionId,nonce:p.nonce,permitSha256:digest(bytes),
    ownerSpkiSha256:trustedOwnerSpkiSha256,
    productionAuthorized:false,networkIsolationVerified:false});
}

/**
 * One-use local nonce claim. Atomic O_EXCL prevents replay on this lab host.
 * This is not a distributed replay ledger and does not attest Owner enrollment.
 */
export function consumeLocalLabNonce(verified,{storePath}={}){
  if(!verified||verified.status!=='OWNER_KEY_SIGNATURE_VERIFIED_FOR_LOCAL_LAB_ONLY'||
     !NONCE.test(verified.nonce||''))
    throw Error('SIGNED_PERMIT_FIRST_REQUIRED');
  if(typeof storePath!=='string'||!isAbsolute(storePath)||
     storePath.length>1024)throw Error('DURABLE_NONCE_STORE_REQUIRED');
  const root=resolve(storePath);
  mkdirSync(root,{recursive:true,mode:0o700});
  const st=lstatSync(root);
  if(st.isSymbolicLink()||!st.isDirectory()||(st.mode&0o077)!==0)
    throw Error('INSECURE_NONCE_STORE');
  const nonceFile=join(root,digest(verified.nonce)+'.used');
  try{
    writeFileSync(nonceFile,JSON.stringify({
      missionId:verified.missionId,permitSha256:verified.permitSha256
    })+'\n',{flag:'wx',mode:0o600});
  }catch(e){
    if(e?.code==='EEXIST')throw Error('SIGNED_LAB_PERMIT_REPLAY_DENIED');
    throw e;
  }
  return {nonceRecorded:true,productionAuthorized:false};
}
