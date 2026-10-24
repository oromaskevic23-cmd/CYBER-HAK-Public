import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {validatePublicRegistries} from "../src/registry-validation.mjs";

const load=(p)=>JSON.parse(readFileSync(new URL("../"+p,import.meta.url),"utf8"));
const originals=()=>({
  manifest:load("PUBLIC-MANIFEST.json"),
  capabilities:load("registry/CAPABILITY-FAMILIES.json"),
  threats:load("registry/THREAT-CATEGORIES.json"),
  severity:load("registry/INCIDENT-SEVERITY.json")
});
const rejected=(mutate,code)=>{
  const x=originals();mutate(x);
  assert.throws(()=>validatePublicRegistries(x),new RegExp(code));
};
test("all checked-in public registries satisfy declared metadata contract",()=>{
  const v=validatePublicRegistries(originals());
  assert.equal(v.status,"PUBLIC_REGISTRY_CONTRACT_PASSED");
  assert.equal(v.family_count,59);
  assert.equal(v.threat_count,30);
  assert.equal(v.severity_count,5);
  assert.equal(v.described_security_agents,10);
  assert.equal(v.governed_skills_declared,512);
  assert.equal(v.execution,"NOT_RUN");
  assert.equal(v.production,"NOT_VERIFIED");
});
test("missing manifest fails closed",()=>rejected(x=>delete x.manifest,"MANIFEST_POLICY_INVALID"));
test("unsafe manifest default denied",()=>rejected(x=>x.manifest.default_policy="ALLOW","MANIFEST_POLICY_INVALID"));
test("private runtime claims not silently allowed",()=>rejected(x=>x.manifest.live_production_runtime="ACTIVE","PRODUCTION_CLAIM_UNSUPPORTED"));
test("public registry never grants execution",()=>rejected(x=>x.capabilities.execution_authority="GRANTED","CAPABILITY_POLICY_INVALID"));
test("count mismatch denied",()=>rejected(x=>x.capabilities.total_capability_families=58,"CAPABILITY_DECLARED_SCALE_MISMATCH"));
test("duplicate capability ID denied",()=>rejected(x=>x.capabilities.families[1].id=x.capabilities.families[0].id,"CAPABILITY_DUPLICATE_ID"));
test("missing capability denied",()=>rejected(x=>x.capabilities.families.pop(),"CAPABILITY_COUNT_MISMATCH"));
test("gap in contiguous capability IDs denied",()=>rejected(x=>x.capabilities.families[1].id="CF-080","CAPABILITY_SEQUENCE_GAP"));
test("capability allow-default denied",()=>rejected(x=>x.capabilities.families[0].default_policy="ALLOW","UNSAFE_CAPABILITY_DEFAULT"));
test("threat registry count mismatch denied",()=>rejected(x=>x.threats.total_threat_categories=31,"THREAT_DECLARED_SCALE_MISMATCH"));
test("duplicate threat denied",()=>rejected(x=>x.threats.categories[0].id=x.threats.categories[1].id,"THREAT_DUPLICATE_ID"));
test("threat allow-default denied",()=>rejected(x=>x.threats.categories[0].default_response="ALLOW","UNSAFE_THREAT_DEFAULT"));
test("severity count mismatch denied",()=>rejected(x=>x.severity.total_severity_levels=6,"SEVERITY_DECLARED_SCALE_MISMATCH"));
test("duplicate severity denied",()=>rejected(x=>x.severity.levels[0].id=x.severity.levels[1].id,"SEVERITY_DUPLICATE_ID"));
test("missing severity index denied",()=>rejected(x=>x.severity.levels[4].id="SEV-9","SEVERITY_INVALID_ID"));
test("manifest must remain public",()=>rejected(x=>x.manifest.classification="SECRET","MANIFEST_POLICY_INVALID"));
