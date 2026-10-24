// Explicit user invocation only. Public GETs; scan results, never source content, go to output.
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {readGitHubRepository,sha256,SHA} from '../src/github-reader.mjs';
import {auditSnapshot,renderMarkdown} from '../src/auditshield.mjs';

const args=process.argv.slice(2);
const knownErrors=new Set(['INVALID_TARGET','TARGET_NOT_AUTHORIZED','GITHUB_TRANSPORT_FAILED','GITHUB_RATE_OR_ACCESS_DENIED',
  'GITHUB_READ_FAILED','RESPONSE_SIZE_LIMIT','RESPONSE_BODY_MISSING','RESPONSE_STREAM_FAILED','INVALID_GITHUB_JSON',
  'PUBLIC_REPOSITORY_REQUIRED','COMMIT_MISMATCH','INCOMPLETE_GIT_TREE','TREE_SIZE_LIMIT','FILE_COUNT_LIMIT',
  'INVALID_TREE_ENTRY','UNSUPPORTED_TREE_ENTRY','FILE_SIZE_LIMIT','TOTAL_SIZE_LIMIT','BLOB_INTEGRITY_MISMATCH',
  'INVALID_SNAPSHOT','INVALID_SNAPSHOT_FILE','SNAPSHOT_INTEGRITY_MISMATCH','INVALID_EXCLUSION']);
if(args.includes('--help')) {
  console.log('Usage: node tools/audit-github.mjs --targets config/audit-targets.json --out audit-output/run-001 [--fail-on-high]');
  console.log('Exit 0: complete scan (may contain findings); 1: HIGH indicator with --fail-on-high; 2: incomplete/error. No raw source or secrets are printed.');
  process.exit(0);
}
let targetsPath='config/audit-targets.json',output='audit-output/run-001',failHigh=false;
try {
  for(let i=0;i<args.length;i++) {
    if(args[i]==='--targets' && args[i+1]) targetsPath=args[++i];
    else if(args[i]==='--out' && args[i+1]) output=args[++i];
    else if(args[i]==='--fail-on-high') failHigh=true;
    else throw new Error('INVALID_ARGUMENT');
  }
  const manifest=JSON.parse(await readFile(resolve(targetsPath),'utf8'));
  if(!Array.isArray(manifest.targets) || manifest.targets.length<1 || manifest.targets.length>10) throw new Error('INVALID_MANIFEST');
  const keys=manifest.targets.map(t=>`${t.repository}@${t.commit}`);
  if(new Set(keys).size!==keys.length) throw new Error('DUPLICATE_TARGET');
  const sourcePaths=['src/github-reader.mjs','src/audit-rules.mjs','src/workflow-audit.mjs','src/auditshield.mjs','tools/audit-github.mjs','package-lock.json'];
  const codeParts=await Promise.all(sourcePaths.map(async p=>p+'\n'+sha256(await readFile(new URL('../'+p,import.meta.url)))));
  const scanner={version:'0.2.0',code_sha256:sha256(codeParts.join('\n')),
    source_commit:SHA.test(process.env.AUDITSHIELD_SOURCE_COMMIT??'')?process.env.AUDITSHIELD_SOURCE_COMMIT:null};
  await mkdir(resolve(output),{recursive:true,mode:0o700});
  const summary={schema:'cyber_hak_auditshield_run_v0.2',scanner,started_at:new Date().toISOString(),targets:[]};
  let incomplete=false,high=false;
  for(const target of manifest.targets) {
    try {
      const snapshot=await readGitHubRepository(target,{allowedTargets:manifest.targets});
      const report={...auditSnapshot(snapshot,{allowedTargets:manifest.targets}),scanner};
      const base=target.repository.replace('/','__')+'__'+target.commit.slice(0,12);
      const json=JSON.stringify(report,null,2)+'\n',md=renderMarkdown(report);
      await writeFile(resolve(output,base+'.json'),json,{flag:'wx',mode:0o600});
      await writeFile(resolve(output,base+'.md'),md,{flag:'wx',mode:0o600});
      const result={repository:report.repository,commit:report.commit,status:report.status,counts:report.counts,
        files:report.coverage.scanned_text_files,report_file:base+'.json',report_sha256:sha256(json)};
      summary.targets.push(result); console.log(JSON.stringify(result));
      incomplete ||= report.status!=='COMPLETE'; high ||= report.counts.HIGH>0;
    } catch (error) {
      // Do not echo remote parser errors, response bodies, filenames or credential-shaped target input.
      const code=knownErrors.has(error.message)?error.message:error.code==='EEXIST'?'OUTPUT_ALREADY_EXISTS':'AUDIT_TARGET_FAILED';
      summary.targets.push({target_index:summary.targets.length,status:'INCOMPLETE',error:code});
      console.error(code+': no clean result is asserted.');
      incomplete=true;
    }
  }
  summary.completed_at=new Date().toISOString(); summary.status=incomplete?'INCOMPLETE':'COMPLETE';
  await writeFile(resolve(output,'summary.json'),JSON.stringify(summary,null,2)+'\n',{flag:'wx',mode:0o600});
  process.exitCode=incomplete?2:failHigh&&high?1:0;
} catch { console.error('AUDIT_RUN_FAILED: invalid configuration or output boundary.');process.exitCode=2; }
