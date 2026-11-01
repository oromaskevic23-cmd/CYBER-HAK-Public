#!/usr/bin/env node
/**
 * Offline Strix Lab host doctor: checks installed local tools only.
 * DOES NOT run Strix, pull images, access cloud APIs, or verify VM firewall.
 */
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const SECRET_ENV=[
  'GITHUB_TOKEN','GH_TOKEN','GH_ADMIN_TOKEN','OPENAI_API_KEY','ANTHROPIC_API_KEY',
  'LLM_API_KEY','AWS_SECRET_ACCESS_KEY','SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_ACCESS_TOKEN','STRIPE_SECRET_KEY'
];
const CHECKS=[
  ['Docker engine','docker',['info','--format','{{.ServerVersion}}']],
  ['Strix version','strix',['--version']],
  ['Ollama version','ollama',['--version']],
  ['Ollama models','ollama',['list']]
];

export function doctor({env=process.env,run=spawnSync}={}){
  if(SECRET_ENV.some(x=>typeof env[x]==='string'&&env[x].length>0))
    throw Error('SECRET_BEARING_HOST_ENV_DENIED');
  if(env.DOCKER_HOST)throw Error('REMOTE_DOCKER_HOST_DENIED');
  const sanitized={PATH:typeof env.PATH==='string'?env.PATH:''};
  const diagnostics=[];let detectedStrixVersion=null;
  for(const [name,command,args] of CHECKS){
    let response;
    try{
      response=run(command,args,{env:sanitized,encoding:'utf8',
        timeout:10000,maxBuffer:128*1024});
    }catch{response=null;}
    if(command==='strix'&&response?.status===0){
      const text=String(response.stdout||'')+' '+String(response.stderr||'');
      detectedStrixVersion=text.match(/(?:^|[^A-Za-z0-9])v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)(?![A-Za-z0-9])/)?.[1]??null;
    }
    diagnostics.push({name,
      state:response?.status===0&&!response?.error&&!response?.signal
        ?'LOCAL_TOOL_REACHABLE':'UNAVAILABLE'});
  }
  const toolsReady=diagnostics.every(x=>x.state==='LOCAL_TOOL_REACHABLE');
  let modelReady=false;
  if(toolsReady&&typeof env.STRIX_LLM==='string'&&
      /^ollama\/[A-Za-z0-9_.:-]{3,100}$/.test(env.STRIX_LLM)){
    const required=env.STRIX_LLM.slice('ollama/'.length);
    let data;
    try{data=run('ollama',['list'],{env:sanitized,encoding:'utf8',
      timeout:10000,maxBuffer:128*1024});}catch{data=null;}
    if(data?.status===0&&typeof data.stdout==='string'){
      const installed=data.stdout.split('\n').slice(1)
        .map(line=>line.trim().split(/\s+/)[0]).filter(Boolean);
      modelReady=installed.includes(required)||
        installed.includes(required+':latest');
    }
  }
  const versionConfigured=typeof env.CYBER_HAK_STRIX_EXPECTED_VERSION==='string'&&
    /^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?$/.test(
      env.CYBER_HAK_STRIX_EXPECTED_VERSION);
  const versionPinMatches=versionConfigured&&
    detectedStrixVersion===env.CYBER_HAK_STRIX_EXPECTED_VERSION;
  return Object.freeze({
    status:toolsReady&&modelReady&&versionPinMatches?
      'LOCAL_COMPONENTS_REACHABLE_ISOLATION_UNVERIFIED':
      'STRIX_LAB_HOST_BLOCKED',
    diagnostics,localModelPresent:modelReady,
    versionPinConfigured:versionConfigured,versionPinMatches,
    hostEgressIsolation:'UNVERIFIED',ownerApproval:'NOT_CHECKED',
    realStrixScanExecuted:false,productionAuthorized:false,
    externalNetworkCalls:0
  });
}

function main(){
  if(process.argv.length!==3||process.argv[2]!=='--doctor')
    throw Error('USAGE_NODE_TOOLS_STRIX_HOST_DOCTOR_MJS_DOCTOR');
  console.log(JSON.stringify(doctor(),null,2));
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{main();}catch(e){
    console.error('CYBER_HAK_DOCTOR_DENIED:'+
      String(e.message).replace(/[^A-Z0-9_]/g,'_'));
    process.exitCode=1;
  }
}
