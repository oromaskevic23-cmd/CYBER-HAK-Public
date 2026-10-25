/**
 * Pinned cross-repository test of ACTUAL public ORION code.
 * No private source or real owner credentials. Independent defensive verification
 * uses ORION's real signed envelopes/report and synthetic ephemeral keys only.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OrionAdvisory,canonicalAdvisoryBytes,ORION_SCHEMA}
 from '../orion_public_reference/src/orion-advisory.mjs';
import {verifyOrionReport} from '../orion_public_reference/src/orion-evidence.mjs';
import {inspectSignedOrionReport} from '../src/orion-guardian-gate.mjs';
const NOW=1792937000000;
const mission='MISSION-ORION-GUARD-001';
const sha=s=>createHash('sha256').update(s).digest('hex');
const fixture=(stances=['FOR','AGAINST','UNSURE'],options={})=>{
 const pairs=stances.map(()=>generateKeyPairSync('ed25519'));
 const trustedDomainPublicKeys=pairs.map((p,i)=>({
  domain_id:'DOMAIN-'+['HANTER','LEGION','NCAQA'][i],public_key:p.publicKey
 }));
 const engine=new OrionAdvisory({trustedDomainPublicKeys,now:()=>NOW});
 const envelopes=stances.map((stance,i)=>{
  const claims={schema:ORION_SCHEMA,mission_id:mission,
   domain_id:trustedDomainPublicKeys[i].domain_id,
   agent_id:'NCA-'+String(i+1).padStart(12,'0'),
   claim_id:'CLAIM-ORION-RELEASE-SAFETY-01',stance,
   evidence_sha256:[sha('fixture-source-'+i),sha('fixture-result-'+i)],
   summary:'Synthetic evidence reference; no real-world correctness established.',
   issued_at:NOW-1000,expires_at:NOW+60000,
   nonce:(i+1).toString(16).padStart(32,'0')};
  return {claims,signature:sign(null,canonicalAdvisoryBytes(claims),
   pairs[i].privateKey).toString('base64url')};
 });
 for(const envelope of envelopes)engine.submit(envelope);
 const report=engine.report(mission);
 assert.equal(verifyOrionReport(report).verified,true);
 return {report,envelopes,trustedDomainPublicKeys,expectedMissionId:mission,now:NOW,
  ownerHalted:false,pairs,...options};
};
const inspect=f=>inspectSignedOrionReport(f);
test('actual 3-domain ORION signed contradictory advisory is held for human review',()=>{
 const x=fixture(),g=inspect(x);
 assert.equal(x.report.claims[0].status,'CONTRADICTION_NEEDS_REVIEW');
 assert.equal(g.decision,'HUMAN_REVIEW_REQUIRED');
 assert.equal(g.reason,'SIGNED_DISAGREEMENT_REVIEW');
 assert.equal(g.signed_advisories_checked,3);
 assert.equal(g.release,'DENIED');assert.equal(g.execution,'DENIED');
 assert.equal(g.source_authority,'NOT_VERIFIED');
 assert.equal(g.evidence_truth_verified,false);
});
test('agreement still cannot grant approval, truth or release',()=>{
 const x=fixture(['FOR','FOR']),g=inspect(x);
 assert.equal(g.decision,'HUMAN_REVIEW_REQUIRED');
 assert.equal(g.reason,'SIGNED_EVIDENCE_REVIEW');
 assert.equal(g.approval,'NOT_GRANTED');
 assert.equal(g.guardian_core,'NOT_DEPLOYED');
});
test('owner halt denies even valid signatures and source hashes',()=>{
 const x=fixture();
 assert.equal(inspect({...x,ownerHalted:true}).decision,'DENY');
 assert.equal(inspect({...x,ownerHalted:true}).reason,'ORION_GUARD_OWNER_HALTED');
});
test('signed message from wrong Ed25519 private key denied',()=>{
 const x=fixture();
 const altered={...x.envelopes[1],signature:sign(null,
  canonicalAdvisoryBytes(x.envelopes[1].claims),x.pairs[0].privateKey).toString('base64url')};
 x.envelopes[1]=altered;
 assert.equal(inspect(x).reason,'ORION_GUARD_SIGNATURE_DENIED');
});
test('signed envelope tampering denied, even when report is old and intact',()=>{
 const x=fixture();
 x.envelopes[0].claims.stance='AGAINST';
 assert.equal(inspect(x).reason,'ORION_GUARD_SIGNATURE_DENIED');
});
test('hash tamper in public ORION report detected',()=>{
 const x=fixture();x.report.claims[0].domain_positions[0].evidence_sha256[0]=sha('evil');
 assert.equal(inspect(x).reason,'ORION_GUARD_REPORT_HASH_MISMATCH');
});
test('self-consistent but fabricated report digest does not bypass signed sources',()=>{
 const x=fixture();
 x.report.claims[0].domain_positions[0].evidence_sha256[0]=sha('evil');
 const body={...x.report};delete body.report_sha256;delete body.audit_last_sha256;
 x.report.report_sha256=sha(JSON.stringify(body));
 assert.equal(inspect(x).reason,'ORION_GUARD_SOURCE_OR_DIGEST_MISMATCH');
});
test('missing one signed domain is coverage denial',()=>{
 const x=fixture();x.envelopes.pop();x.trustedDomainPublicKeys.pop();
 assert.equal(inspect(x).reason,'ORION_GUARD_COVERAGE_MISMATCH');
});
test('extra privileged fields in signed claim fail closed',()=>{
 const x=fixture();x.envelopes[0].claims.execute=true;
 assert.equal(inspect(x).reason,'ORION_GUARD_CLAIM_INVALID');
});
test('duplicate domain keys never count as independent trust',()=>{
 const x=fixture();x.trustedDomainPublicKeys[1].public_key=x.trustedDomainPublicKeys[0].public_key;
 assert.equal(inspect(x).reason,'ORION_GUARD_DUPLICATE_DOMAIN_KEY');
});
test('expired signed claim denied at time of guardian review',()=>{
 const x=fixture();x.now=NOW+61000;
 assert.equal(inspect(x).reason,'ORION_GUARD_CLAIM_INVALID');
});
test('signed report cannot claim verified truth or production release',()=>{
 const x=fixture();x.report.truth_verified=true;
 assert.equal(inspect(x).reason,'ORION_GUARD_REPORT_BOUNDARY_DENIED');
 const y=fixture();y.report.release='APPROVED';
 assert.equal(inspect(y).reason,'ORION_GUARD_REPORT_BOUNDARY_DENIED');
});
test('unknown trusted-domain substitution denied',()=>{
 const x=fixture();x.trustedDomainPublicKeys[0].domain_id='DOMAIN-ROGUE';
 assert.equal(inspect(x).reason,'ORION_GUARD_DOMAIN_OR_REPLAY_DENIED');
});
test('duplicate nonce for same domain denied',()=>{
 const x=fixture();x.envelopes[1].claims.domain_id=x.envelopes[0].claims.domain_id;
 x.envelopes[1].claims.nonce=x.envelopes[0].claims.nonce;
 assert.equal(inspect(x).decision,'DENY');
});
test('no raw synthetic advisory text or private keys in guardian receipt',()=>{
 const x=fixture(),result=inspect(x);
 assert.equal(result.decision,'HUMAN_REVIEW_REQUIRED');
 assert(!JSON.stringify(result).includes('Synthetic evidence reference'));
 assert(!JSON.stringify(result).includes('PRIVATE KEY'));
});
test('invalid or missing report input is always DENY',()=>{
 const x=fixture();
 assert.equal(inspect({...x,report:null}).decision,'DENY');
 assert.equal(inspect({}).decision,'DENY');
});
