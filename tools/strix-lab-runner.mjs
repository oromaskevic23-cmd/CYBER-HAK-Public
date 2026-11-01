#!/usr/bin/env node
/**
 * CYBER HAK × Strix — owner-operated, isolated, LOCAL/OFFLINE lab runner.
 *
 * No network URL targets, no production credentials, no automatic execution.
 * The Strix sandbox may have network access: a truly egress-filtered disposable
 * host is an external prerequisite; this CLI cannot enforce host networking.
 */
import {spawnSync} from 'node:child_process';
import {cpSync,existsSync,lstatSync,mkdtempSync,mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const SOURCE_DIRS=Object.freeze(['src','test','tools']);
const SOURCE_FILES=Object.freeze(['package.json']);
const modes=new Set(['--preflight','--run']);
const allowedBase=new Set(['http://127.0.0.1:11434','http://localhost:11434']);

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
  if(['LLM_API_KEY','OPENAI_API_KEY','ANTHROPIC_API_KEY','GITHUB_TOKEN','GH_TOKEN',
       'SUPABASE_SERVICE_ROLE_KEY','LLM_EXTRA_HEADERS'].some(k=>env[k]))
    throw Error('PRIVILEGED_OR_EXTERNAL_SECRET_ENV_DENIED');
  return {status:'LOCAL_LAB_ADMISSIBLE_NOT_SCANNED',mode,
    target:'DISPOSABLE_PUBLIC_SOURCE_COPY_ONLY',externalEffects:0};
}

function verifyNoLinks(path){
  if(lstatSync(path).isSymbolicLink())throw Error('SYMLINK_SOURCE_DENIED');
  if(lstatSync(path).isDirectory()){
    const {readdirSync}=fsShim;
    for(const x of readdirSync(path))verifyNoLinks(join(path,x));
  }
}
const fsShim=await import('node:fs');

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
    PATH:process.env.PATH,HOME:undefined,DOCKER_HOST:undefined,
    STRIX_LLM:process.env.STRIX_LLM,LLM_API_BASE:process.env.LLM_API_BASE,
    PYTHONUNBUFFERED:'1'
  };
  command('docker',['info','--format','{{.ServerVersion}}'],process.env);
  command('strix',['--version'],process.env);
  const work=mkdtempSync(join(tmpdir(),'cyber-hak-strix-lab-'));
  const staged=join(work,'public-source');
  mkdirSync(staged,{mode:0o700});
  for(const dir of SOURCE_DIRS){
    const p=join(root,dir);
    if(!existsSync(p))throw Error('REQUIRED_SOURCE_MISSING');
    verifyNoLinks(p);
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
  console.log(JSON.stringify({status:'STRIX_LOCAL_SCAN_STARTING',
    target:'DISPOSABLE_COPY',production:false,cloud:false,
    evidenceDir:work}));
  const proc=spawnSync('strix',[
    '-n','--target',staged,'--scan-mode','quick','--scope-mode','full',
    '--max-turns','80','--instruction-file',join(work,'SCOPE.md')
  ],{cwd:work,env:safeEnv,stdio:'inherit',timeout:30*60*1000});
  if(proc.error||proc.signal)throw Error('STRIX_EXECUTION_ERROR');
  // Source and evidence remain in private mode-0700 temp directory on host.
  // Do not publish raw Strix PoCs or logs to public GitHub.
  console.log(JSON.stringify({status:'STRIX_PROCESS_COMPLETED',
    exitCode:proc.status,evidenceDir:work,production:false}));
  process.exitCode=proc.status??1;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  main().catch(e=>{
    console.error('CYBER_HAK_STRIX_DENIED:'+String(e.message).replace(/[^A-Z0-9_]/g,'_'));
    process.exitCode=1;
  });
}
