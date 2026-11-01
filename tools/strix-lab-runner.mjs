#!/usr/bin/env node
/**
 * CYBER HAK × Strix — owner-operated, isolated, LOCAL/OFFLINE lab runner.
 *
 * No network URL targets, no production credentials, no automatic execution.
 * The Strix sandbox may have network access: a truly egress-filtered disposable
 * host is an external prerequisite; this CLI cannot enforce host networking.
 */
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {cpSync,existsSync,lstatSync,mkdtempSync,mkdirSync,readdirSync,readFileSync,writeFileSync,openSync,closeSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join,relative} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const SOURCE_DIRS=Object.freeze(['src','test','tools']);
const SOURCE_FILES=Object.freeze(['package.json']);
const modes=new Set(['--preflight','--run']);
const allowedBase=new Set(['http://127.0.0.1:11434','http://localhost:11434']);
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const LAB_BUDGET_USD='0.01'; // defense in depth on top of local-model-only admission
const MAX_SOURCE_FILES=1000,MAX_SOURCE_BYTES=15*1024*1024;

export function sourceFingerprint(folder) {
  const base=resolve(folder),manifest=[];let bytes=0;
  function collect(p){
    const info=lstatSync(p);
    if(info.isSymbolicLink())throw Error('SYMLINK_SOURCE_DENIED');
    if(info.isDirectory()){
      for(const name of readdirSync(p).sort())collect(join(p,name));
      return;
    }
    if(!info.isFile()||info.nlink!==1)throw Error('UNSAFE_SOURCE_FILE_TYPE');
    if(info.size>1024*1024)throw Error('SOURCE_FILE_SIZE_DENIED');
    const data=readFileSync(p);
    if(data.length!==info.size)throw Error('SOURCE_MUTATED_DURING_SCAN');
    bytes+=data.length;
    manifest.push({path:relative(base,p).replaceAll('\\','/'),sha256:sha(data),bytes:data.length});
    if(manifest.length>MAX_SOURCE_FILES||bytes>MAX_SOURCE_BYTES)throw Error('SOURCE_TREE_LIMIT_DENIED');
  }
  collect(base);
  if(!manifest.length)throw Error('EMPTY_SOURCE_SNAPSHOT_DENIED');
  manifest.sort((a,b)=>a.path.localeCompare(b.path));
  return Object.freeze({sha256:sha(JSON.stringify(manifest)),fileCount:manifest.length,bytes});
}

export function assessScanEvidence({exitCode,runStatus,findingsCount,evidencePresent,
  endTime,reportedTarget,expectedTarget,spentUsd,limitUsd=Number(LAB_BUDGET_USD)}={}) {
  if(!Number.isInteger(exitCode)||![0,1,2].includes(exitCode))return 'STRIX_PROCESS_UNVERIFIED';
  if(exitCode===1)return 'STRIX_FATAL_ERROR';
  if(evidencePresent!==true||!Number.isSafeInteger(findingsCount)||findingsCount<0)
    return 'STRIX_EVIDENCE_INCOMPLETE';
  if(runStatus!=='completed')return 'STRIX_INCOMPLETE_OR_STOPPED';
  // Upstream Strix run.json reports end_time and llm_usage.cost.
  // A CLI exit code zero can reflect premature wrap-up near a budget cap.
  if((typeof endTime!=='string'||!Number.isFinite(Date.parse(endTime))) &&
     !(typeof endTime==='number'&&Number.isFinite(endTime)&&endTime>0))
    return 'STRIX_COMPLETION_NOT_ATTESTED';
  if(typeof reportedTarget!=='string'||typeof expectedTarget!=='string'||
     !reportedTarget||reportedTarget!==expectedTarget)
    return 'STRIX_SCOPE_NOT_ATTESTED';
  if(typeof spentUsd!=='number'||!Number.isFinite(spentUsd)||spentUsd<0||
     !Number.isFinite(limitUsd)||limitUsd<=0)
    return 'STRIX_BUDGET_NOT_ATTESTED';
  if(spentUsd>=limitUsd*0.90)return 'STRIX_BUDGET_COVERAGE_UNVERIFIED';
  if(exitCode===0&&findingsCount===0)return 'STRIX_REPORTED_NO_FINDINGS_QA_PENDING';
  if(exitCode===2&&findingsCount>0)return 'STRIX_REPORTED_FINDINGS_QA_PENDING';
  return 'STRIX_EXIT_AND_EVIDENCE_DISAGREE';
}

function parseEvidenceFile(p){
  const stat=lstatSync(p);
  if(stat.isSymbolicLink()||!stat.isFile()||stat.size>5*1024*1024)
    throw Error('UNSAFE_STRIX_REPORT_FILE');
  return JSON.parse(readFileSync(p,'utf8'));
}
export function inspectStrixArtifacts(work,exitCode) {
  const base=join(work,'strix_runs'),expectedTarget=join(work,'public-source');
  if(!existsSync(base))return {status:'STRIX_EVIDENCE_INCOMPLETE',findingsCount:null};
  if(lstatSync(base).isSymbolicLink()||!lstatSync(base).isDirectory())
    throw Error('UNSAFE_STRIX_RUNS_DIRECTORY');
  const entries=readdirSync(base,{withFileTypes:true});
  if(entries.length!==1||!entries[0].isDirectory())
    return {status:'STRIX_EVIDENCE_INCOMPLETE',findingsCount:null};
  const run=join(base,entries[0].name);
  if(lstatSync(run).isSymbolicLink()||!lstatSync(run).isDirectory())
    throw Error('UNSAFE_STRIX_RUN_DIRECTORY');
  const runFile=join(run,'run.json'),vulns=join(run,'vulnerabilities.json');
  if(!existsSync(runFile)||!existsSync(vulns))
    return {status:'STRIX_EVIDENCE_INCOMPLETE',findingsCount:null};
  const metadata=parseEvidenceFile(runFile), findingsData=parseEvidenceFile(vulns);
  const findings=Array.isArray(findingsData)?findingsData:
    Array.isArray(findingsData?.vulnerabilities)?findingsData.vulnerabilities:
    Array.isArray(findingsData?.findings)?findingsData.findings:null;
  const findingsCount=findings?.length??null;
  const reportedTargets=Array.isArray(metadata?.targets_info)?metadata.targets_info
    .map(t=>t?.original).filter(s=>typeof s==='string'):[];
  const reportedTarget=reportedTargets.length===1?reportedTargets[0]:null;
  const spentUsd=metadata?.llm_usage?.cost;
  return {status:assessScanEvidence({exitCode,runStatus:metadata?.status,
      findingsCount,evidencePresent:findings!==null,
      endTime:metadata?.end_time,reportedTarget,expectedTarget,spentUsd}),
    findingsCount,runStatus:typeof metadata?.status==='string'?metadata.status:null,
    costAttested:Number.isFinite(spentUsd)&&spentUsd>=0,
    targetMatches:reportedTarget===expectedTarget,
    runJsonSha256:sha(readFileSync(runFile)),
    vulnerabilityIndexSha256:sha(readFileSync(vulns)),
    independentQA:false};
}


export function assessRuntime(env={},mode='--preflight') {
  if(!modes.has(mode))throw Error('UNSUPPORTED_STRIX_MODE');
  const requirements=[
    {name:'Docker daemon',state:'NOT_VERIFIED'},
    {name:'Strix CLI',state:'NOT_VERIFIED'},
    {name:'Ollama local model with structured tools',state:'NOT_VERIFIED'},
    {name:'Isolated disposable host with outbound deny',state:'NOT_VERIFIED'}
  ];
  if(mode==='--preflight')
    return {status:'PREFLIGHT_ONLY_NOT_SCANNED',mode,requirements,externalEffects:0};
  if(env.CYBER_HAK_STRIX_LOCAL_RUN!=='EXPLICITLY_APPROVED')
    throw Error('OWNER_APPROVAL_REQUIRED');
  if(env.CYBER_HAK_STRIX_ISOLATED_HOST!=='CONFIRMED')
    throw Error('EGRESS_ISOLATION_NOT_ATTESTED');
  if(typeof env.STRIX_LLM!=='string'||!/^ollama\/[A-Za-z0-9_.:-]{3,100}$/.test(env.STRIX_LLM))
    throw Error('LOCAL_OLLAMA_MODEL_REQUIRED');
  if(!allowedBase.has(env.LLM_API_BASE))throw Error('LOOPBACK_LLM_BASE_REQUIRED');
  if(typeof env.CYBER_HAK_STRIX_EXPECTED_VERSION!=='string'||
     !/^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?$/.test(env.CYBER_HAK_STRIX_EXPECTED_VERSION))
    throw Error('PINNED_STRIX_VERSION_REQUIRED');
  if(['LLM_API_KEY','OPENAI_API_KEY','ANTHROPIC_API_KEY','GITHUB_TOKEN','GH_TOKEN',
       'SUPABASE_SERVICE_ROLE_KEY','LLM_EXTRA_HEADERS','GITHUB_ADMIN_TOKEN',
       'SUPABASE_ACCESS_TOKEN','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY',
       'GOOGLE_APPLICATION_CREDENTIALS','STRIPE_SECRET_KEY'].some(k=>env[k]))
    throw Error('PRIVILEGED_OR_EXTERNAL_SECRET_ENV_DENIED');
  return {status:'LOCAL_LAB_ADMISSIBLE_NOT_SCANNED',mode,
    target:'DISPOSABLE_PUBLIC_SOURCE_COPY_ONLY',externalEffects:0};
}

function verifyNoLinks(path){
  if(lstatSync(path).isSymbolicLink())throw Error('SYMLINK_SOURCE_DENIED');
  if(lstatSync(path).isDirectory()){
    for(const x of readdirSync(path))verifyNoLinks(join(path,x));
  }
}

function command(cmd,args,env,{cwd=root,timeout=15000}={}){
  const result=spawnSync(cmd,args,{cwd,env,timeout,encoding:'utf8',stdio:'pipe'});
  if(result.error||result.status!==0)throw Error(cmd.toUpperCase().replace(/[^A-Z]/g,'_')+'_UNAVAILABLE');
  return result;
}

async function main(){
  if(process.argv.length!==3||!modes.has(process.argv[2]))
    throw Error('USAGE_NODE_TOOLS_STRIX_LAB_RUNNER_MJS_PREFLIGHT_OR_RUN');
  const mode=process.argv[2];
  const plan=assessRuntime(process.env,mode);
  if(mode==='--preflight'){
    console.log(JSON.stringify(plan,null,2));
    return;
  }
  const safeEnv={
    PATH:process.env.PATH,
    STRIX_LLM:process.env.STRIX_LLM,LLM_API_BASE:process.env.LLM_API_BASE,
    PYTHONUNBUFFERED:'1'
  };
  command('docker',['info','--format','{{.ServerVersion}}'],safeEnv);
  const version=command('strix',['--version'],safeEnv);
  const foundVersions=((version.stdout||'')+'\n'+(version.stderr||''))
    .match(/[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?/g)||[];
  if(!foundVersions.includes(process.env.CYBER_HAK_STRIX_EXPECTED_VERSION))
    throw Error('STRIX_VERSION_MISMATCH');
  const work=mkdtempSync(join(tmpdir(),'cyber-hak-strix-lab-'));
  const staged=join(work,'public-source');
  mkdirSync(staged,{mode:0o700});
  for(const dir of SOURCE_DIRS){
    const p=join(root,dir);
    if(!existsSync(p))throw Error('REQUIRED_SOURCE_MISSING');
    verifyNoLinks(p);
    sourceFingerprint(p);
    cpSync(p,join(staged,dir),{recursive:true,dereference:false});
  }
  for(const name of SOURCE_FILES){
    const p=join(root,name);
    if(!existsSync(p))throw Error('REQUIRED_SOURCE_MISSING');
    verifyNoLinks(p);
    cpSync(p,join(staged,name),{dereference:false});
  }
  const guide=join(root,'security','strix','SCOPE.md');
  verifyNoLinks(guide);
  cpSync(guide,join(work,'SCOPE.md'));
  safeEnv.HOME=join(work,'home');
  mkdirSync(safeEnv.HOME,{mode:0o700});
  const sourceBefore=sourceFingerprint(staged);
  writeFileSync(join(work,'source-provenance.json'),JSON.stringify({
    schema:'cyber-hak.strix.source-provenance.v2',
    source:sourceBefore,scopeSha256:sha(readFileSync(join(work,'SCOPE.md'))),
    expectedStrixVersion:process.env.CYBER_HAK_STRIX_EXPECTED_VERSION,
    model:process.env.STRIX_LLM,budgetUsd:LAB_BUDGET_USD,
    productionAuthorized:false
  },null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({status:'STRIX_LOCAL_SCAN_STARTING_NO_QA',
    sourceSha256:sourceBefore.sha256,production:false}));
  // Untrusted Strix output is private to the disposable host, NOT streamed to CI.
  const fd=openSync(join(work,'strix-private.log'),'wx',0o600);
  let proc;
  try{
    proc=spawnSync('strix',[
      '-n','--target',staged,'--scan-mode','quick','--scope-mode','full',
      '--max-turns','80','--max-budget',LAB_BUDGET_USD,
      '--instruction-file',join(work,'SCOPE.md')
    ],{cwd:work,env:safeEnv,stdio:['ignore',fd,fd],timeout:30*60*1000});
  }finally{closeSync(fd);}
  const sourceAfter=sourceFingerprint(staged);
  const evidence=proc.error||proc.signal?
    {status:'STRIX_PROCESS_ERROR',findingsCount:null}:
    inspectStrixArtifacts(work,proc.status);
  const receipt={
    schema:'cyber-hak.strix.execution-receipt.v2',
    ...evidence,exitCode:proc.status??null,
    sourceSha256Before:sourceBefore.sha256,
    sourceSha256After:sourceAfter.sha256,
    sourceChanged:sourceBefore.sha256!==sourceAfter.sha256,
    independentQA:false,productionAuthorized:false,
    externalEffectsNotIndependentlyVerified:true,
    note:'NO PRODUCTION RELEASE; QA and actual host isolation proof required'
  };
  writeFileSync(join(work,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',
    {flag:'wx',mode:0o600});
  console.log(JSON.stringify({status:receipt.status,evidenceDir:work,
    sourceSha256:sourceBefore.sha256,independentQA:false}));
  // A candidate finding remains an exit-2 block until independently accepted.
  process.exitCode=receipt.status==='STRIX_REPORTED_NO_FINDINGS_QA_PENDING'?0:
    receipt.status==='STRIX_REPORTED_FINDINGS_QA_PENDING'?2:1;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  main().catch(e=>{
    console.error('CYBER_HAK_STRIX_DENIED:'+String(e.message).replace(/[^A-Z0-9_]/g,'_'));
    process.exitCode=1;
  });
}
