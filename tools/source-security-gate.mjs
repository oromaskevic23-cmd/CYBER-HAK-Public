#!/usr/bin/env node
/**
 * CYBER HAK — original offline source-security audit / PR gate.
 * Founding Architect: Alexander Nikolaevich Romaskevich (RomaskevicH).
 * Original module contributors: see AUTHORS.md and Git history.
 * No target code execution, outbound traffic, secrets or external scanning.
 * Match = policy signal requiring triage, NOT a confirmed vulnerability.
 */
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {constants,openSync,closeSync,fstatSync,readFileSync,lstatSync,writeFileSync} from 'node:fs';
import {resolve,relative,isAbsolute,sep,join,basename} from 'node:path';
import {TextDecoder} from 'node:util';
import {fileURLToPath} from 'node:url';

const sha = data => createHash('sha256').update(data).digest('hex');
const REPO = resolve(fileURLToPath(new URL('..',import.meta.url)));
const MAX_FILES = 30000, MAX_BYTES = 64 * 1024 * 1024, MAX_FILE = 1024 * 1024;
const RELEVANT = /\.(?:m?js|cjs|ts|tsx|jsx|py|go|rs|java|sh|bash|ya?ml|json|toml|env|txt|md|tf|hcl)$/i;
const utf8 = new TextDecoder('utf-8',{fatal:true});
const git = (root,args) => execFileSync('git',['-C',root,...args],{
  encoding:'buffer',timeout:12000,maxBuffer:8*1024*1024,
  env:{PATH:process.env.PATH||'/usr/bin:/bin',HOME:'/nonexistent',GIT_CONFIG_NOSYSTEM:'1'}
});
const splits = b => b.toString('utf8').split('\0').filter(Boolean);
const allowed = p => typeof p==='string' && p.length>0 && !isAbsolute(p) &&
  !p.includes('\\') && !p.split('/').some(x=>x===''||x==='.'||x==='..');
const relevant = p => RELEVANT.test(p) || basename(p).startsWith('.env') ||
  basename(p)==='Dockerfile' || p==='.github/CODEOWNERS';
const workflow = p => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(p);

export function scanText(p,raw) {
  const rows = raw.split(/\r?\n/);
  const signals = [], add=(rule,line,policy) => signals.push({
    rule_id:rule,path:p,line,classification:'STATIC_POLICY_SIGNAL',
    policy,validated_exploit:false,
    fingerprint:sha([rule,p,line].join('|')).slice(0,24)
  });
  // Concatenate sentinels so that the scanner's own source is not a secret fixture.
  const keyStart='-----'+'BEGIN ';
  const pem = new RegExp(keyStart+'(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----');
  const token = /(?:gh[pousr]_[A-Za-z0-9]{32,}|github_pat_[A-Za-z0-9_]{50,}|AKIA[0-9A-Z]{16})/;
  for(let i=0;i<rows.length;i++) {
    const row=rows[i],n=i+1;
    if(pem.test(row))add('CHAK-SECRET-001',n,'PRIVATE_KEY_MATERIAL_IN_TRACKED_SOURCE');
    if(token.test(row))add('CHAK-SECRET-002',n,'HIGH_CONFIDENCE_TOKEN_SHAPE_REVIEW');
    if(!workflow(p))continue;
    if(/^\s*permissions:\s*(?:write-all)\s*(?:#.*)?$/i.test(row))
      add('CHAK-CI-001',n,'OVERBROAD_WORKFLOW_PERMISSIONS');
    const action=row.match(/^\s*-\s*uses:\s*([^\s#]+)\s*(?:#.*)?$/);
    if(action) {
      const ref=action[1];
      if(!ref.startsWith('./') && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/i.test(ref)
          && !/^docker:\/\/[^\s]+@sha256:[0-9a-f]{64}$/i.test(ref))
        add('CHAK-CI-002',n,'ACTION_REFERENCE_NOT_IMMUTABLY_PINNED');
    }
    if(/^\s*pull_request_target:\s*(?:#.*)?$/.test(row))
      add('CHAK-CI-003',n,'PR_TARGET_TRUST_BOUNDARY_NEEDS_REVIEW');
    if(/\b(?:curl|wget)\b.{0,180}\|\s*(?:sudo\s+)?(?:bash|sh)\b/.test(row))
      add('CHAK-CI-004',n,'REMOTE_SCRIPT_PIPE_TO_SHELL');
  }
  return signals;
}

export function scanRepository({root=REPO,base=null}={}) {
  root=resolve(root);
  const commit=git(root,['rev-parse','HEAD']).toString('utf8').trim();
  if(!/^[0-9a-f]{40}$/.test(commit))throw Error('GIT_HEAD_NOT_VERIFIABLE');
  const tracked=splits(git(root,['ls-files','-z','--cached']));
  if(tracked.length>MAX_FILES)throw Error('SOURCE_FILE_COUNT_LIMIT');
  let selected=tracked;
  if(base!==null) {
    if(typeof base!=='string'||!/^[0-9a-f]{40}$/.test(base)||/^0{40}$/.test(base))
      throw Error('EXACT_BASE_COMMIT_REQUIRED');
    git(root,['cat-file','-e',base+'^{commit}']);
    const changed=new Set(splits(git(root,['diff','--name-only','--diff-filter=ACMR','-z',base+'...HEAD'])));
    selected=tracked.filter(p=>changed.has(p));
  }
  const findings=[], inspected=[], skipped=[];
  let bytes=0;
  for(const path of [...selected].sort()) {
    if(!allowed(path))throw Error('PATH_OUTSIDE_TRACKED_TREE');
    if(!relevant(path)){skipped.push({path,reason:'NON_TEXT_RULESET_SCOPE'});continue;}
    const full=join(root,...path.split('/'));
    const stat=lstatSync(full);
    if(stat.isSymbolicLink()||!stat.isFile()||stat.size>MAX_FILE)
      throw Error('UNSAFE_TRACKED_SOURCE_OR_SIZE: '+path);
    const fd=openSync(full,constants.O_RDONLY|constants.O_NOFOLLOW);
    let data;
    try {
      const before=fstatSync(fd);
      if(!before.isFile()||before.size>MAX_FILE)throw Error('UNSAFE_FILE_DESCRIPTOR');
      data=readFileSync(fd);
      const after=fstatSync(fd);
      if(data.length!==before.size||after.size!==before.size||
        after.ino!==before.ino||after.dev!==before.dev)
        throw Error('SOURCE_CHANGED_DURING_AUDIT');
    }finally{closeSync(fd)}
    bytes+=data.length;
    if(bytes>MAX_BYTES)throw Error('SOURCE_TOTAL_BYTES_LIMIT');
    let raw;
    try{raw=utf8.decode(data)}catch{throw Error('INVALID_UTF8_TRACKED_SOURCE: '+path)}
    inspected.push({path,sha256:sha(data),bytes:data.length});
    findings.push(...scanText(path,raw));
  }
  findings.sort((a,b)=>a.path.localeCompare(b.path)||a.line-b.line||a.rule_id.localeCompare(b.rule_id));
  const sourceManifest=sha(JSON.stringify(inspected));
  const report={
    schema:'imperial.cyber-hak.source-security-gate.v1',
    owner:'oromaskevic23-cmd',source_commit:commit,base_commit:base,
    scope:base===null?'TRACKED_SOURCE_FULL':'TRACKED_SOURCE_CHANGED_ONLY',
    execution:'READ_ONLY_STATIC_SOURCE_ANALYSIS',network_used:false,
    policy_rules:['CHAK-SECRET-001','CHAK-SECRET-002','CHAK-CI-001',
                  'CHAK-CI-002','CHAK-CI-003','CHAK-CI-004'],
    scanned_files:inspected.length,scanned_bytes:bytes,skipped_files:skipped.length,
    skipped_reasons:skipped,source_manifest_sha256:sourceManifest,
    findings,policy_signals:findings.length,
    independent_qa_verified:false,coverage_complete:false,
    no_vulnerabilities_claimed:false,production_authorized:false,
    result:findings.length?'POLICY_REVIEW_REQUIRED':'NO_SIGNALS_IN_LIMITED_STATIC_RULESET'
  };
  return {...report,report_sha256:sha(JSON.stringify(report))};
}

export function main(argv=process.argv.slice(2)) {
  let base=null,root=REPO,output=null,enforce=false;
  for(let i=0;i<argv.length;i++) {
    const x=argv[i];
    if(x==='--root')root=argv[++i];
    else if(x==='--base')base=argv[++i];
    else if(x==='--report')output=argv[++i];
    else if(x==='--enforce')enforce=true;
    else throw Error('UNKNOWN_OR_INCOMPLETE_ARGUMENT: '+x);
  }
  if(!root || (base!==null && !base) || (output!==null&&!output))
    throw Error('MISSING_REQUIRED_ARGUMENT_VALUE');
  const report=scanRepository({root,base});
  const summary={schema:report.schema,source_commit:report.source_commit,
    scope:report.scope,scanned_files:report.scanned_files,
    policy_signals:report.policy_signals,result:report.result,
    report_sha256:report.report_sha256,coverage_complete:false};
  console.log(JSON.stringify(summary));
  if(output) {
    const target=resolve(output),source=resolve(root);
    if(target===source||target.startsWith(source+sep))throw Error('OUTPUT_MUST_BE_OUTSIDE_SCANNED_TREE');
    writeFileSync(target,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  }
  return enforce&&report.findings.length?3:0;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try{process.exitCode=main()}catch(err){
    console.error('CYBER_HAK_AUDIT_INCOMPLETE',err.message);
    process.exitCode=2;
  }
}
