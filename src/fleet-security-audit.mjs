/** CYBER HAK defensive, read-only repository security policy engine.
 * Input is *metadata and reviewed workflow text*, not arbitrary remote instructions.
 * Does not execute code, call a network API, change access, or claim external alerts were checked.
 */
import {createHash} from 'node:crypto';
const sha=s=>createHash('sha256').update(s).digest('hex');
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const fullSha=s=>/^[a-f0-9]{40}$/i.test(s);
const maxFindings=2000;

export function auditRepo({name,visibility,paths,workflows,alertCoverage='UNAVAILABLE',inventoryComplete=true}={}) {
  if(typeof name!=='string'||!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(name)||
     !['public','private','internal'].includes(visibility)||!Array.isArray(paths)||
     paths.some(p=>typeof p!=='string'||p.length>420)||!object(workflows))
    throw Error('INVALID_INPUT');
  if(!['VERIFIED','UNAVAILABLE','NOT_ENABLED','ACCESS_DENIED'].includes(alertCoverage))
    throw Error('INVALID_ALERT_COVERAGE');
  const unique=[...new Set(paths)];
  if(unique.length!==paths.length)throw Error('DUPLICATE_PATHS');
  const found=[];
  const add=(id,severity,path,detail)=>found.push({id,severity,path,detail});
  const badFiles=unique.filter(p=>/(^|\/)(?:\.env(?:\.(?!example|sample|template)[^/]*)?|id_rsa|id_ed25519|credentials(?:\.json|\.yaml|\.yml)?|[^/]+\.(?:pem|p12|pfx|key))$/i.test(p));
  for(const p of badFiles)add('SENSITIVE_PATH_TRACKED','HIGH',p,'Review tracked sensitive-looking filename; content not exposed');
  const workflowNames=unique.filter(p=>/^\.github\/workflows\/[^/]+\.ya?ml$/.test(p));
  const supplied=Object.keys(workflows);
  if(supplied.some(p=>!workflowNames.includes(p)))throw Error('WORKFLOW_NOT_IN_TREE');
  for(const p of workflowNames){
    if(!Object.hasOwn(workflows,p)||typeof workflows[p]!=='string'){
      add('WORKFLOW_NOT_READ','INCOMPLETE',p,'Workflow source could not be inspected');
      continue;
    }
    const text=workflows[p];
    if(text.length>150000){add('WORKFLOW_TOO_LARGE','INCOMPLETE',p,'Workflow exceeds review size limit');continue;}
    const usages=[...text.matchAll(/^\s*(?:-\s*)?uses:\s*['"]?([^\s#'"]+)/gm)].map(m=>m[1]);
    for(const action of usages){
      if(action.startsWith('./'))continue;
      const at=action.lastIndexOf('@');
      if(at<1||!fullSha(action.slice(at+1)))add('MUTABLE_ACTION_REF','MEDIUM',p,'Action is not pinned to a full commit SHA');
    }
    if(!/^\s*permissions:\s*(?:\{\s*\})?\s*$/m.test(text)&&
       !/^\s*permissions:\s*\{[^}]+\}/m.test(text)){
      add('MISSING_EXPLICIT_PERMISSIONS','MEDIUM',p,'Workflow has no explicit token permissions');
    }
    const elevated=/^\s*(?:contents|issues|packages|pull-requests|actions|deployments|id-token):\s*write\s*(?:#.*)?$/m.test(text);
    const triggers=/^\s*(?:pull_request_target|issue_comment|issues|workflow_run|repository_dispatch):\s*/m.test(text);
    if(elevated&&triggers)add('ELEVATED_EVENT_TOKEN','HIGH',p,'Write token on externally influenced event; review trust boundaries');
    if(/(?:curl|wget)[^\n]{0,200}\|\s*(?:bash|sh)\b/m.test(text))
      add('PIPE_TO_SHELL','HIGH',p,'Remote script piped directly into shell');
    if(/^\s*(?:-\s*)?run:\s*[^\n]*\$\{\{\s*(?:github\.event|github\.head_ref|inputs\.)/m.test(text))
      add('DIRECT_UNTRUSTED_SHELL_INTERPOLATION','HIGH',p,'Untrusted context interpolated into run command');
    if(/^\s*uses:\s*['"]?actions\/checkout@/m.test(text)&&elevated&&triggers&&
       /persist-credentials:\s*true/.test(text))
      add('ELEVATED_CHECKOUT_CREDENTIALS','HIGH',p,'Write token retained in git workspace');
  }
  if(!inventoryComplete)add('INCOMPLETE_TREE','INCOMPLETE','(repository)','Cannot claim exhaustive file-tree coverage');
  if(alertCoverage!=='VERIFIED')add('DEPENDENCY_AND_SECRET_ALERTS_NOT_VERIFIED','INCOMPLETE','(GitHub Security)',alertCoverage);
  if(found.length>maxFindings)throw Error('TOO_MANY_FINDINGS');
  const severity={HIGH:0,MEDIUM:1,LOW:2,INCOMPLETE:3};
  found.sort((a,b)=>severity[a.severity]-severity[b.severity]||a.path.localeCompare(b.path)||a.id.localeCompare(b.id));
  const summary={high:found.filter(x=>x.severity==='HIGH').length,
    medium:found.filter(x=>x.severity==='MEDIUM').length,
    incomplete:found.filter(x=>x.severity==='INCOMPLETE').length};
  const report={schema:'cyber-hak.readonly-fleet-audit.v1',repo:name,visibility,
    pathCount:unique.length,workflowCount:workflowNames.length,
    checkedWorkflows:workflowNames.length-found.filter(x=>x.id==='WORKFLOW_NOT_READ'||x.id==='WORKFLOW_TOO_LARGE').length,
    alertCoverage,inventoryComplete,summary,findings:found,
    decision:summary.high||summary.medium?'REMEDIATION_REQUIRED':summary.incomplete?'INCOMPLETE':'POLICY_GATE_PASS',
    claim:'STATIC_REPOSITORY_POLICY_ONLY_NO_EXPLOIT_OR_FULL_SCA',
    externalEffects:0};
  return {...report,evidenceSha256:sha(JSON.stringify(report))};
}

/**
 * Verify the *complete* content-addressed audit envelope before aggregation.
 * SHA-256 is an accidental-corruption checksum, NOT a signature or proof of origin:
 * fleet inventory evidence still requires separate trusted collection and signing.
 */
export function verifyRepoEvidence(report) {
  if(!object(report) ||
     Object.keys(report).sort().join('|') !==
       ['schema','repo','visibility','pathCount','workflowCount','checkedWorkflows',
        'alertCoverage','inventoryComplete','summary','findings','decision','claim',
        'externalEffects','evidenceSha256'].sort().join('|')) throw Error('REPORT_SCHEMA_DENIED');
  const full=/^[a-f0-9]{64}$/;
  if(report.schema!=='cyber-hak.readonly-fleet-audit.v1' ||
    typeof report.repo!=='string' ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(report.repo) ||
    !['public','private','internal'].includes(report.visibility) ||
    !['VERIFIED','UNAVAILABLE','NOT_ENABLED','ACCESS_DENIED'].includes(report.alertCoverage) ||
    typeof report.inventoryComplete!=='boolean' ||
    report.externalEffects!==0 ||
    report.claim!=='STATIC_REPOSITORY_POLICY_ONLY_NO_EXPLOIT_OR_FULL_SCA' ||
    !full.test(report.evidenceSha256)) throw Error('REPORT_PROVENANCE_INVALID');
  for(const key of ['pathCount','workflowCount','checkedWorkflows']){
    if(!Number.isSafeInteger(report[key]) || report[key]<0 || report[key]>1000000)
      throw Error('REPORT_COUNTS_INVALID');
  }
  if(report.checkedWorkflows>report.workflowCount || report.workflowCount>report.pathCount)
    throw Error('REPORT_COUNTS_INVALID');
  if(!Array.isArray(report.findings) || report.findings.length>maxFindings ||
      report.findings.some(f=>!object(f)||
        Object.keys(f).sort().join('|')!=='detail|id|path|severity' ||
        !['HIGH','MEDIUM','LOW','INCOMPLETE'].includes(f.severity) ||
        ![f.id,f.path,f.detail].every(s=>typeof s==='string'&&s.length>0&&s.length<=600)))
    throw Error('REPORT_FINDINGS_INVALID');
  if(!object(report.summary) ||
    Object.keys(report.summary).sort().join('|')!=='high|incomplete|medium')
    throw Error('REPORT_SUMMARY_INVALID');
  const tally={
    high:report.findings.filter(f=>f.severity==='HIGH').length,
    medium:report.findings.filter(f=>f.severity==='MEDIUM').length,
    incomplete:report.findings.filter(f=>f.severity==='INCOMPLETE').length
  };
  if(Object.keys(tally).some(k=>report.summary[k]!==tally[k]))
    throw Error('REPORT_SUMMARY_MISMATCH');
  const expectedDecision=tally.high||tally.medium?'REMEDIATION_REQUIRED':
    tally.incomplete?'INCOMPLETE':'POLICY_GATE_PASS';
  if(report.decision!==expectedDecision) throw Error('REPORT_DECISION_MISMATCH');
  const {evidenceSha256,...unsigned}=report;
  if(sha(JSON.stringify(unsigned))!==evidenceSha256)
    throw Error('REPORT_SHA256_MISMATCH');
  return true;
}

/**
 * Require an independently supplied exact-name inventory before full fleet PASS.
 * Caller-supplied names must come from a trusted owner-maintained inventory;
 * this module cannot attest their origin or sign them.
 */
export function auditFleet(reports,{expectedRepos=30,expectedRepoNames=null}={}) {
  if(!Array.isArray(reports)||!Number.isSafeInteger(expectedRepos)||
     expectedRepos<1||expectedRepos>100000||reports.length>expectedRepos)
    throw Error('FLEET_SCHEMA');
  const names=reports.map(x=>x?.repo);
  if(names.some(x=>typeof x!=='string')||new Set(names).size!==names.length)
    throw Error('DUPLICATE_FLEET_REPOS');
  for(const r of reports)verifyRepoEvidence(r);
  let membershipVerified=false,inventorySha256=null;
  if(expectedRepoNames!==null){
    if(!Array.isArray(expectedRepoNames)||expectedRepoNames.length!==expectedRepos||
       expectedRepoNames.some(n=>typeof n!=='string'||
         !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(n))||
       new Set(expectedRepoNames).size!==expectedRepos)
      throw Error('TRUSTED_INVENTORY_SCHEMA_DENIED');
    const expected=new Set(expectedRepoNames);
    membershipVerified=names.length===expectedRepos&&names.every(n=>expected.has(n));
    inventorySha256=sha(JSON.stringify([...expected].sort()));
  }
  const report={schema:'cyber-hak.fleet-attestation.v3',
    expectedRepos,observedRepos:reports.length,
    membershipVerified,inventorySha256,
    complete:membershipVerified&&reports.every(r=>
      r.inventoryComplete&&r.alertCoverage==='VERIFIED'&&
      r.checkedWorkflows===r.workflowCount&&r.summary.incomplete===0&&
      r.decision==='POLICY_GATE_PASS'),
    high:reports.reduce((a,r)=>a+r.summary.high,0),
    medium:reports.reduce((a,r)=>a+r.summary.medium,0),
    incomplete:reports.reduce((a,r)=>a+r.summary.incomplete,0),
    outcome:'UNVERIFIED',externalEffects:0};
  report.outcome=report.complete&&report.high===0&&report.medium===0&&
    report.incomplete===0?'POLICY_GATE_PASS':'REVIEW_REQUIRED';
  return {...report,evidenceSha256:sha(JSON.stringify(report))};
}
