import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {mkdtempSync,rmSync,mkdirSync,symlinkSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
 permitSigningBytes,verifySignedLabPermit,consumeLocalLabNonce
} from '../security/strix/signed-permit.mjs';

const now=Date.parse('2026-11-01T14:30:00Z');
const hex=x=>createHash('sha256').update(x).digest('hex');
function fixture(){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const pem=publicKey.export({type:'spki',format:'pem'});
 const pin=hex(publicKey.export({type:'spki',format:'der'}));
 const payload={
   schema:'cyber-hak.strix.owner-lab-permit.v1',
   missionId:'IC-STRIX-LAB-0001',
   targetSha256:'a'.repeat(64),scopeSha256:'b'.repeat(64),
   model:'ollama/qwen3-vl',strixVersion:'1.2.3',
   nonce:'synthetic_nonce_0123456789',
   issuedAt:now-1000,expiresAt:now+120000,
   productionAuthorized:false,externalTargetsAuthorized:false,
   maxBudgetUsd:'0.01'
 };
 const issue=(p=payload)=>({
  payload:p,
  signature:sign(null,permitSigningBytes(p),privateKey).toString('base64url')
 });
 const verify=(permit=issue(),values={})=>verifySignedLabPermit({
   permit,ownerPublicKeyPem:pem,trustedOwnerSpkiSha256:pin,
   expectedTargetSha256:payload.targetSha256,
   expectedScopeSha256:payload.scopeSha256,
   expectedModel:payload.model,expectedVersion:payload.strixVersion,
   expectedBudgetUsd:'0.01',now,...values
 });
 return {payload,issue,verify,pem,pin,publicKey,privateKey};
}

test('ephemeral Ed25519 synthetic owner permit binds exact local lab source and scope',()=>{
 const f=fixture();
 const got=f.verify();
 assert.equal(got.status,'OWNER_KEY_SIGNATURE_VERIFIED_FOR_LOCAL_LAB_ONLY');
 assert.equal(got.ownerSpkiSha256,f.pin);
 assert.equal(got.networkIsolationVerified,false);
 assert.equal(got.productionAuthorized,false);
 assert.match(got.permitSha256,/^[a-f0-9]{64}$/);
});

test('same payload signed by unrelated issuer is denied by pinned SPKI trust root',()=>{
 const f=fixture(),stranger=fixture();
 assert.throws(()=>f.verify(stranger.issue()),/PERMIT_SIGNATURE_REJECTED/);
 assert.throws(()=>f.verify(f.issue(),{trustedOwnerSpkiSha256:'0'.repeat(64)}),
   /UNTRUSTED_OWNER_PUBLIC_KEY/);
});

test('signature cannot be reused after source bytes or security scope change',()=>{
 const f=fixture();
 assert.throws(()=>f.verify(f.issue(),{expectedTargetSha256:'c'.repeat(64)}),
   /LAB_SCOPE_BINDING_MISMATCH/);
 assert.throws(()=>f.verify(f.issue(),{expectedScopeSha256:'d'.repeat(64)}),
   /LAB_SCOPE_BINDING_MISMATCH/);
 assert.throws(()=>f.verify(f.issue(),{expectedModel:'ollama/foreign'}),
   /LAB_SCOPE_BINDING_MISMATCH/);
 assert.throws(()=>f.verify(f.issue(),{expectedVersion:'2.0.0'}),
   /LAB_SCOPE_BINDING_MISMATCH/);
 assert.throws(()=>f.verify(f.issue(),{expectedBudgetUsd:'9.99'}),
   /LAB_SCOPE_BINDING_MISMATCH/);
});

test('tampering after signature destroys authorization',()=>{
 const f=fixture(),permit=f.issue();
 const tampered={...permit,payload:{...permit.payload,nonce:'replacement_nonce_1234567890'}};
 assert.throws(()=>f.verify(tampered),/PERMIT_SIGNATURE_REJECTED/);
});

test('expired, future and overly long grants are denied',()=>{
 const f=fixture();
 assert.throws(()=>f.verify(f.issue(),{now:now+300000}),/PERMIT_SCOPE_OR_TTL_DENIED/);
 const future={...f.payload,issuedAt:now+20000,expiresAt:now+50000};
 assert.throws(()=>f.verify(f.issue(future)),/PERMIT_SCOPE_OR_TTL_DENIED/);
 const long={...f.payload,expiresAt:now+700000};
 assert.throws(()=>f.verify(f.issue(long)),/PERMIT_SCOPE_OR_TTL_DENIED/);
});

test('permissions to production or external targets are always forbidden',()=>{
 const f=fixture();
 for(const change of [{productionAuthorized:true},{externalTargetsAuthorized:true}]){
  const altered={...f.payload,...change};
  assert.throws(()=>f.verify(f.issue(altered)),/PERMIT_SCOPE_OR_TTL_DENIED/);
 }
});

test('arbitrary or missing permit fields and noncanonical signature are rejected',()=>{
 const f=fixture(),p=f.issue();
 assert.throws(()=>f.verify(null),/SIGNED_LAB_PERMIT_REQUIRED/);
 assert.throws(()=>f.verify({...p,payload:{...p.payload,admin:true}}),
   /PERMIT_SCHEMA_DENIED/);
 assert.throws(()=>f.verify({...p,signature:'invalid%%%'}),
   /PERMIT_SIGNATURE_INVALID/);
});

test('only Ed25519 keys are accepted, not RSA or HMAC-like impersonation',()=>{
 const f=fixture();
 const {publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const pem=publicKey.export({type:'spki',format:'pem'});
 assert.throws(()=>f.verify(f.issue(),{
   ownerPublicKeyPem:pem,
   trustedOwnerSpkiSha256:hex(publicKey.export({type:'spki',format:'der'}))
 }),/OWNER_ED25519_REQUIRED/);
});

test('durable exclusive local nonce claim is rejected on replay',t=>{
 const f=fixture(),verified=f.verify();
 const root=mkdtempSync(join(tmpdir(),'cyber-hak-lab-nonce-'));
 t.after(()=>rmSync(root,{force:true,recursive:true}));
 const store=join(root,'store');
 assert.equal(consumeLocalLabNonce(verified,{storePath:store}).nonceRecorded,true);
 assert.throws(()=>consumeLocalLabNonce(verified,{storePath:store}),
   /SIGNED_LAB_PERMIT_REPLAY_DENIED/);
});

test('world-writable nonce directory is rejected before claim',t=>{
 const f=fixture(),verified=f.verify();
 const root=mkdtempSync(join(tmpdir(),'cyber-hak-nonce-insecure-'));
 t.after(()=>rmSync(root,{force:true,recursive:true}));
 const store=join(root,'unsafe');mkdirSync(store,{mode:0o777});
 chmodSync(store,0o777);
 assert.throws(()=>consumeLocalLabNonce(verified,{storePath:store}),
   /INSECURE_NONCE_STORE/);
});

test('symlink nonce store cannot redirect one-time admission',t=>{
 const f=fixture(),verified=f.verify();
 const root=mkdtempSync(join(tmpdir(),'cyber-hak-nonce-symlink-'));
 t.after(()=>rmSync(root,{force:true,recursive:true}));
 const actual=join(root,'real');mkdirSync(actual,{mode:0o700});
 symlinkSync(actual,join(root,'alias'));
 assert.throws(()=>consumeLocalLabNonce(verified,{storePath:join(root,'alias')}),
   /INSECURE_NONCE_STORE/);
});

test('permit signer is separate from CYBER HAK code and never grants scanner runtime rights',()=>{
 const f=fixture(),v=f.verify();
 assert.equal(v.productionAuthorized,false);
 assert.equal(v.networkIsolationVerified,false);
 assert(!('privateKey' in v));
});
