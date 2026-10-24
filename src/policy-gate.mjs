// CYBER HAK — pure policy decision only. No tools, no attacks, no production changes.
import {createHash,createHmac,timingSafeEqual} from "node:crypto";
const ACTIONS = Object.freeze({
  T0:["inspect_public_registry","review_public_artifact"],
  T1:["inspect_owned_asset_metadata"],
  T2:["review_isolated_lab_evidence"],
  T3:[]
});
const DOMAINS={T0:"PUBLIC_METADATA",T1:"OWNED_ASSET",T2:"ISOLATED_LAB"};
const IDENTIFIER=/^[A-Za-z0-9_-]{6,80}$/;
const NONCE=/^[A-Za-z0-9_-]{12,80}$/;
const HEX=/^[a-f0-9]{64}$/;
const MAX_TTL=5*60*1000;
const digest=s=>createHash("sha256").update(s).digest("hex");
const deny=(code,request)=>Object.freeze({
  decision:"DENY",reason:code,execution:"NOT_RUN",release:"DENIED",
  request_sha256:digest(JSON.stringify(request??null)),
  evidence_level:"E2_POLICY_REFERENCE_NOT_RUNTIME"
});
function safeRequest(r) {
  return !!r&&typeof r==="object"&&!Array.isArray(r)&&
    IDENTIFIER.test(r.missionId??"")&&
    ["T0","T1","T2","T3"].includes(r.tier)&&
    typeof r.action==="string"&&
    typeof r.domain==="string"&&
    typeof r.target==="string"&&r.target.length>=3&&r.target.length<=200&&
    !/[\u0000-\u001f\u007f]/.test(r.target)&&
    Object.keys(r).every(k=>["missionId","tier","action","domain","target"].includes(k));
}
function equals(a,b) {
  return Buffer.byteLength(a)===Buffer.byteLength(b)&&
    timingSafeEqual(Buffer.from(a),Buffer.from(b));
}
function verifyApproval(token,secret,now) {
  if(typeof secret!=="string"||Buffer.byteLength(secret)<32||Buffer.byteLength(secret)>4096)
    return {ok:false,reason:"AUTHENTICATION_KEY_UNAVAILABLE"};
  if(typeof token!=="string"||token.length>2500||token.split(".").length!==2)
    return {ok:false,reason:"INVALID_APPROVAL_TOKEN"};
  const [encoded,signature]=token.split(".");
  if(!/^[A-Za-z0-9_-]+$/.test(encoded)||!HEX.test(signature))
    return {ok:false,reason:"INVALID_APPROVAL_TOKEN"};
  const bytes=Buffer.from(encoded,"base64url");
  if(bytes.toString("base64url")!==encoded)return {ok:false,reason:"NONCANONICAL_TOKEN"};
  const mac=createHmac("sha256",secret).update(bytes).digest("hex");
  if(!equals(signature,mac))return {ok:false,reason:"BAD_APPROVAL_SIGNATURE"};
  let a;try{a=JSON.parse(bytes.toString("utf8"));}catch{return {ok:false,reason:"INVALID_APPROVAL_PAYLOAD"};}
  if(!a||typeof a!=="object"||Array.isArray(a)||Object.keys(a).length!==11||
     !["version","issuer","humanApproved","missionId","tier","action","domain","target","nonce","issuedAt","expiresAt"].every(k=>Object.hasOwn(a,k)))
     return {ok:false,reason:"INVALID_APPROVAL_PAYLOAD"};
  if(a.version!=="cyber_hak_reference_permit_v1"||a.issuer!=="OWNER"||a.humanApproved!==true||
     !NONCE.test(a.nonce??"")||!Number.isSafeInteger(a.issuedAt)||
     !Number.isSafeInteger(a.expiresAt)||!Number.isSafeInteger(now)||
     a.issuedAt>now+5000||a.expiresAt<=now||a.expiresAt<=a.issuedAt||
     a.expiresAt-a.issuedAt>MAX_TTL)
     return {ok:false,reason:"INVALID_OR_EXPIRED_APPROVAL"};
  return {ok:true,data:a};
}

// The permit signer is deliberately EXTERNAL to this package; possession of a mission ID is not approval.
// An in-memory replay set is not a distributed revocation system or independent human authentication.
export function decideSecurityAction({request,permit,verificationKey,seenNonces,now=Date.now()}={}) {
  if(!safeRequest(request))return deny("INVALID_REQUEST",request);
  if(request.tier==="T3")return deny("T3_ALWAYS_DENY",request);
  if(!ACTIONS[request.tier].includes(request.action)||DOMAINS[request.tier]!==request.domain)
    return deny("CAPABILITY_OR_DOMAIN_DENIED",request);
  if(!(seenNonces instanceof Set))return deny("REPLAY_STORE_REQUIRED",request);
  const approval=verifyApproval(permit,verificationKey,now);
  if(!approval.ok)return deny(approval.reason,request);
  const a=approval.data;
  if(["missionId","tier","action","domain","target"].some(k=>a[k]!==request[k]))
    return deny("APPROVAL_SCOPE_MISMATCH",request);
  if(seenNonces.has(a.nonce))return deny("REPLAY_DETECTED",request);
  seenNonces.add(a.nonce);
  return Object.freeze({decision:"PERMITTED_FOR_REVIEW_ONLY",
    reason:"SCOPED_REFERENCE_APPROVAL_VERIFIED",mission_id:request.missionId,
    tier:request.tier,action:request.action,
    request_sha256:digest(JSON.stringify(request)),
    evidence_level:"E2_POLICY_REFERENCE_NOT_RUNTIME",
    execution:"NOT_RUN",release:"DENIED"});
}
