import test from "node:test";
import assert from "node:assert/strict";
import {createHmac} from "node:crypto";
import {decideSecurityAction} from "../src/policy-gate.mjs";

const KEY="test-only-key-for-cyber-hak-unit-test-32-bytes";
const NOW=1780000000000;
const mission={missionId:"MISSION-001",tier:"T0",action:"inspect_public_registry",
  domain:"PUBLIC_METADATA",target:"registry/CAPABILITY-FAMILIES.json"};
function sign(request=mission,extra={}) {
  const p={version:"cyber_hak_reference_permit_v1",issuer:"OWNER",
    humanApproved:true,...request,nonce:"nonce-unit-test-001",
    issuedAt:NOW,expiresAt:NOW+60000,...extra};
  const raw=Buffer.from(JSON.stringify(p),"utf8");
  return raw.toString("base64url")+"."+createHmac("sha256",KEY).update(raw).digest("hex");
}
const run=(opts={})=>decideSecurityAction({
  request:mission,permit:sign(),verificationKey:KEY,
  seenNonces:new Set(),now:NOW+1000,...opts
});
test("valid scoped permit grants review, never action execution",()=>{
 const r=run();
 assert.equal(r.decision,"PERMITTED_FOR_REVIEW_ONLY");
 assert.equal(r.execution,"NOT_RUN");
 assert.equal(r.release,"DENIED");
 assert.match(r.request_sha256,/^[a-f0-9]{64}$/);
});
test("default-deny invalid requests and arbitrary actions",()=>{
 for(const request of [null,{}, {...mission,action:"read_private_keys"},
   {...mission,domain:"SECRET"},{...mission,target:"a"}, {...mission,owner:true}]){
   assert.equal(run({request}).decision,"DENY");
 }
});
test("prohibited T3 is always denied even when locally signed",()=>{
 const request={...mission,tier:"T3",action:"inspect_public_registry"};
 const result=run({request,permit:sign(request)});
 assert.equal(result.decision,"DENY");
 assert.equal(result.reason,"T3_ALWAYS_DENY");
});
test("T1 and T2 require tier-appropriate action and domain",()=>{
 for(const request of [
  {...mission,tier:"T1",action:"inspect_public_registry",domain:"PUBLIC_METADATA"},
  {...mission,tier:"T2",action:"inspect_public_registry",domain:"PUBLIC_METADATA"},
  {...mission,tier:"T0",action:"inspect_owned_asset_metadata",domain:"OWNED_ASSET"},
 ]){
  const r=run({request,permit:sign(request)});
  assert.equal(r.decision,"DENY");
  assert.equal(r.reason,"CAPABILITY_OR_DOMAIN_DENIED");
 }
});
test("separately scoped authorized T1 and T2 remain review-only",()=>{
 for(const request of [
   {...mission,tier:"T1",action:"inspect_owned_asset_metadata",domain:"OWNED_ASSET"},
   {...mission,tier:"T2",action:"review_isolated_lab_evidence",domain:"ISOLATED_LAB"}
 ]){
  const r=run({request,permit:sign(request)});
  assert.equal(r.decision,"PERMITTED_FOR_REVIEW_ONLY");
  assert.equal(r.execution,"NOT_RUN");
 }
});
test("unauthenticated tokens are denied",()=>{
 for(const permit of [undefined,"","a.b",sign()+"garbage"]){
   assert.equal(run({permit}).decision,"DENY");
 }
});
test("invalid and missing shared signing key cannot pass",()=>{
 for(const verificationKey of ["weak",undefined,"x".repeat(9000)]){
   const r=run({verificationKey});
   assert.equal(r.decision,"DENY");
   assert.equal(r.reason,"AUTHENTICATION_KEY_UNAVAILABLE");
 }
});
test("signed approval is strictly bound to exact mission scope",()=>{
 const request={...mission,target:"registry/THREAT-CATEGORIES.json"};
 const r=run({request});
 assert.equal(r.decision,"DENY");
 assert.equal(r.reason,"APPROVAL_SCOPE_MISMATCH");
});
test("expired, future, or excessive-duration approval fails closed",()=>{
 for(const extra of [
   {expiresAt:NOW+999},
   {issuedAt:NOW+60000,expiresAt:NOW+100000},
   {expiresAt:NOW+400000}
 ]){
  const r=run({permit:sign(mission,extra)});
  assert.equal(r.decision,"DENY");
 }
});
test("replay of approved permit is denied",()=>{
 const seenNonces=new Set();
 assert.equal(run({seenNonces}).decision,"PERMITTED_FOR_REVIEW_ONLY");
 const second=run({seenNonces});
 assert.equal(second.decision,"DENY");
 assert.equal(second.reason,"REPLAY_DETECTED");
});
test("missing replay tracker is denied",()=>{
 assert.equal(run({seenNonces:undefined}).reason,"REPLAY_STORE_REQUIRED");
});
test("tampered signature is denied",()=>{
 const token=sign();
 const [data,signature]=token.split(".");
 const altered=(signature[0]==="a"?"b":"a")+signature.slice(1);
 assert.equal(run({permit:data+"."+altered}).reason,"BAD_APPROVAL_SIGNATURE");
});
test("signed self-authorization is rejected",()=>{
 const token=sign(mission,{issuer:"AGENT",humanApproved:true});
 const r=run({permit:token});
 assert.equal(r.reason,"INVALID_OR_EXPIRED_APPROVAL");
});
test("signed approval for a prohibited high-risk action remains denied",()=>{
 const request={...mission,tier:"T2",action:"delete_evidence",domain:"ISOLATED_LAB"};
 assert.equal(run({request,permit:sign(request)}).reason,"CAPABILITY_OR_DOMAIN_DENIED");
});
