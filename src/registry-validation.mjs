// CYBER HAK: offline defensive public-registry validator. No execution authority.
const requireCheck=(x,code)=>{if(!x)throw new Error(code);};
const family=/^CF-[0-9]{3}$/;
const threat=/^TM-[0-9]{2}$/;
const severity=/^SEV-[0-4]$/;
function verifyCollection(rows,size,pattern,label) {
  requireCheck(Array.isArray(rows)&&rows.length===size,label+"_COUNT_MISMATCH");
  const ids=new Set();
  for(const item of rows) {
    requireCheck(item && typeof item==="object"&&!Array.isArray(item) &&
      typeof item.id==="string"&&pattern.test(item.id),label+"_INVALID_ID");
    requireCheck(!ids.has(item.id),label+"_DUPLICATE_ID");
    requireCheck(typeof item.name==="string"&&item.name.length>=2,label+"_INVALID_NAME");
    ids.add(item.id);
  }
  return ids;
}
export function validatePublicRegistries({manifest,capabilities,threats,severity:severityData}={}) {
  requireCheck(manifest?.public_repository===true&&
    manifest.classification==="PUBLIC"&&manifest.default_policy==="DENY"&&
    manifest.t3_policy==="ALWAYS_DENY","MANIFEST_POLICY_INVALID");
  requireCheck(manifest.private_hanter_runtime_published===false &&
    manifest.live_production_runtime==="NOT_VERIFIED"&&
    manifest.production_authorization==="NOT_AUTHORIZED","PRODUCTION_CLAIM_UNSUPPORTED");
  requireCheck(capabilities?.classification==="PUBLIC"&&
    capabilities.default_policy==="DENY"&&
    capabilities.execution_authority==="NONE_BY_REGISTRY","CAPABILITY_POLICY_INVALID");
  requireCheck(manifest.capability_families===59&&
    manifest.governed_security_skills===512&&manifest.security_nca===10,
    "MANIFEST_DECLARED_SCALE_MISMATCH");
  requireCheck(capabilities.total_capability_families===59&&
    capabilities.governed_security_skills===512&&capabilities.security_nca===10,
    "CAPABILITY_DECLARED_SCALE_MISMATCH");
  const families=verifyCollection(capabilities.families,59,family,"CAPABILITY");
  for(let i=1;i<=59;i++)
    requireCheck(families.has("CF-"+String(i).padStart(3,"0")),"CAPABILITY_SEQUENCE_GAP");
  requireCheck(capabilities.families.every(f=>f.default_policy==="DENY_UNLESS_GOVERNED"),
    "UNSAFE_CAPABILITY_DEFAULT");
  requireCheck(threats?.classification==="PUBLIC"&&threats.default_policy==="DENY"&&
    threats.total_threat_categories===30&&manifest.threat_categories===30,
    "THREAT_DECLARED_SCALE_MISMATCH");
  const ids=verifyCollection(threats.categories,30,threat,"THREAT");
  for(let i=1;i<=30;i++)
    requireCheck(ids.has("TM-"+String(i).padStart(2,"0")),"THREAT_SEQUENCE_GAP");
  requireCheck(threats.categories.every(t=>t.default_response==="DENY_UNLESS_EXPLICITLY_GOVERNED"),
    "UNSAFE_THREAT_DEFAULT");
  requireCheck(severityData?.classification==="PUBLIC"&&
    severityData.total_severity_levels===5&&manifest.incident_severity_levels===5,
    "SEVERITY_DECLARED_SCALE_MISMATCH");
  const sv=verifyCollection(severityData.levels,5,severity,"SEVERITY");
  for(let i=0;i<5;i++)
    requireCheck(sv.has("SEV-"+i),"SEVERITY_SEQUENCE_GAP");
  return Object.freeze({status:"PUBLIC_REGISTRY_CONTRACT_PASSED",
    family_count:families.size,threat_count:ids.size,
    severity_count:sv.size,described_security_agents:manifest.security_nca,
    governed_skills_declared:manifest.governed_security_skills,
    execution:"NOT_RUN",production:"NOT_VERIFIED"});
}
