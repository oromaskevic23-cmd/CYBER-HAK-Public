/** CYBER HAK AuditShield: local/private checkout defensive scan.
 * This tool must execute in a separate checked/pinned auditor checkout.
 * Never prints source text or copies it into the public repository.
 */
import {readFile,lstat,mkdir,writeFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {resolve,join,relative} from 'node:path';
import {createHash} from 'node:crypto';
import {scanText,RULES,displayPath} from '../src/audit-rules.mjs';
import {scanWorkflow} from '../src/workflow-audit.mjs';
const run=promisify(execFile);
const deny=x=>{throw Error(x)};
const digest=x=>createHash('sha256').update(x).digest('hex');
const SHA=/^[0-9a-f]{40}$/,SAFE=/^(?:src|test|scripts|\.github\/workflows)\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;
export const AUDIT_FILES=Object.freeze([
 'src/nca-universal-live-gates.mjs','src/nca-sandbox-boundary.mjs',
 'src/nca-signed-proofgraph.mjs','src/nca-durable-permit-ledger.mjs',
 'test/nca-universal-live-gates.test.mjs','test/nca-sandbox-boundary.test.mjs',
 'scripts/nca-live-llm-ci.mjs','scripts/nca-docker-sandbox-trial.mjs',
 '.github/workflows/nca-next-priority.yml'
]);
export function scanSelectedEvidence(entries,{sourceSha,scannerSha}={}){
 if(!SHA.test(sourceSha)||!SHA.test(scannerSha)||!Array.isArray(entries)||
    entries.length!==AUDIT_FILES.length)deny('CHECKOUT_COVERAGE_INCOMPLETE');
 const names=new Set(),findings=[],coverage=[];
 for(const file of entries){
  if(!file||!SAFE.test(file.path)||!AUDIT_FILES.includes(file.path)||names.has(file.path)||
     typeof file.content!=='string'||Buffer.byteLength(file.content)>256*1024)
   deny('CHECKOUT_SOURCE_INVALID');
  names.add(file.path);
  const result=scanText(file);
  if(file.path.endsWith('.yml')||file.path.endsWith('.yaml')){
   const s=scanWorkflow(file.content);
   if(!s.complete)deny('WORKFLOW_SEMANTIC_COVERAGE_INCOMPLETE');
   result.push(...s.findings);
  }
  if(result.some(x=>x.rule_id==='ANALYSIS_LIMIT'))deny('SCANNER_COVERAGE_EXHAUSTED');
  coverage.push({path:displayPath(file.path),sha256:digest(file.content),
    bytes:Buffer.byteLength(file.content)});
  const dedup=new Set();
  for(const entry of result){
   const key=entry.rule_id+':'+entry.line;
   if(dedup.has(key))continue;
   dedup.add(key);
   const rule=RULES[entry.rule_id];
   if(!rule)deny('AUDIT_RULE_UNKNOWN');
   findings.push({id:digest(file.path+'|'+sourceSha+'|'+key).slice(0,24),
    path:displayPath(file.path),line:entry.line,rule_id:entry.rule_id,
    severity:rule[0],evidence:rule[1],recommendation:rule[2]});
  }
 }
 if(names.size!==AUDIT_FILES.length||AUDIT_FILES.some(p=>!names.has(p)))deny('CHECKOUT_COVERAGE_INCOMPLETE');
 const counts={HIGH:0,MEDIUM:0,LOW:0};
 for(const f of findings)counts[f.severity]++;
 return {schema:'cyber_hak_private_checkout_assessment_v1',sourceSha,scannerSha,
   sourceVisibility:'PRIVATE',acquisition:'LOCAL_VERIFIED_GIT_CHECKOUT_READ_ONLY',
   scope:'NINE_SELECTED_SECURITY_CRITICAL_FILES_NOT_WHOLE_REPOSITORY',
   status:'COMPLETE',verdict:counts.HIGH>0?'HIGH_RISK_REVIEW_REQUIRED':
     findings.length?'REVIEW_REQUIRED':'NO_INDICATORS_IN_SCOPE',
   counts,coverage,findings,
   sourceCodeExported:false,personalDataCollected:false,privateKeyRead:false,
   humanReviewer:'NOT_ASSIGNED',independentHumanAcceptance:false,
   productionRelease:'DENIED',knownLimitations:['Static indicators only','No runtime escape or container breakout test',
    'No proof of secret absence outside nine selected paths','No direct model-provider or host security validation',
    'Automated tool separation is not independent human sign-off']};
}
export async function scanGitCheckout({root,expectedSha,scannerSha,output}={}){
 if(typeof root!=='string'||!root.startsWith('/')||typeof output!=='string'||!output.startsWith('/')||
  !SHA.test(expectedSha)||!SHA.test(scannerSha))deny('AUDIT_INPUT_DENIED');
 const directory=resolve(root),destination=resolve(output);
 if(directory===destination||destination.startsWith(directory+'/'))deny('OUTPUT_INSIDE_SOURCE_DENIED');
 const [git,listing]=await Promise.all([
  run('git',['rev-parse','HEAD'],{cwd:directory,timeout:5000,maxBuffer:100000}),
  run('git',['ls-files','-z','--',...AUDIT_FILES],{cwd:directory,timeout:5000,maxBuffer:100000})
 ]);
 if(git.stdout.trim()!==expectedSha)deny('COMMIT_MISMATCH');
 const listed=listing.stdout.split('\0').filter(Boolean);
 if(listed.length!==AUDIT_FILES.length||AUDIT_FILES.some(p=>!listed.includes(p)))deny('TRACKED_SCOPE_INCOMPLETE');
 const entries=[];
 for(const p of AUDIT_FILES){
  const file=join(directory,p);const stat=await lstat(file);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>256*1024)deny('LOCAL_SOURCE_UNSAFE');
  const buffer=await readFile(file);
  if(buffer.includes(0))deny('BINARY_SOURCE_UNSUPPORTED');
  const decoded=new TextDecoder('utf-8',{fatal:true}).decode(buffer);
  entries.push({path:p,content:decoded});
 }
 const report=scanSelectedEvidence(entries,{sourceSha:expectedSha,scannerSha});
 await mkdir(destination,{recursive:true,mode:0o700});
 await writeFile(join(destination,'cyber-hak-private-review.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
 return report;
}
