import {authorizeTarget,gitBlobSha,sha256,requireAudit,validGitPath} from './github-reader.mjs';
import {RULES,scanText,displayPath} from './audit-rules.mjs';
import {scanWorkflow,scanContainerConfig} from './workflow-audit.mjs';

export const LIMITATIONS = Object.freeze([
  'Static indicators only; no claim of exploitability, credential validity or absence of vulnerabilities.',
  'One exact public Git revision per target; no commit history, other branches, issues, PR artifacts, releases or GitHub administration settings.',
  'No source execution, dependency vulnerability database, dynamic data-flow analysis, malware engine, sandbox or production scan.',
  'Private repositories are rejected by this anonymous public-reader version. No credentials are read from the environment or tested.',
  'Binary/non-UTF-8 files, symlinks, submodules and LFS objects are coverage gaps. Unsupported YAML aliases/tags and parse failures make the audit incomplete.',
  'Known-pattern and entropy heuristics can miss encoded, split or unfamiliar secrets; exact placeholders and repeated synthetic suffixes are not secret alerts.',
  'The invocation allowlist constrains scope; it is not an AI Passport, signed permit, human authentication or production Approval Gateway.'
]);
export function auditSnapshot(snapshot, {allowedTargets=[]}={}) {
  authorizeTarget(snapshot,allowedTargets);
  requireAudit(Array.isArray(snapshot.files) && Array.isArray(snapshot.exclusions) &&
    snapshot.files.length+snapshot.exclusions.length===snapshot.tree_file_count && snapshot.tree_file_count<=500, 'INVALID_SNAPSHOT');
  const paths=new Set(), files=[], findings=[], gaps=[];
  for(const file of snapshot.files) {
    requireAudit(validGitPath(file.path) && !paths.has(file.path) && typeof file.content==='string','INVALID_SNAPSHOT_FILE');
    paths.add(file.path);
    const bytes=Buffer.from(file.content,'utf8');
    requireAudit(bytes.length<=262144 && bytes.length===file.bytes && gitBlobSha(bytes)===file.blob_sha && sha256(bytes)===file.content_sha256,'SNAPSHOT_INTEGRITY_MISMATCH');
    let items=scanText(file);
    if(items.some(f=>f.rule_id==='ANALYSIS_LIMIT')) gaps.push({path:displayPath(file.path),reason:'FINDING_LIMIT_REACHED'});
    let semantic={findings:[],complete:true};
    if(/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(file.path)) semantic=scanWorkflow(file.content);
    else if(/(?:^|\/)(?:docker-compose|compose)(?:\.[^/]+)?\.ya?ml$/i.test(file.path) || /^k8s\/.*\.ya?ml$/i.test(file.path)) semantic=scanContainerConfig(file.content);
    if(!semantic.complete) gaps.push({path:displayPath(file.path),reason:'SEMANTIC_ANALYSIS_INCOMPLETE'});
    items=items.concat(semantic.findings);
    const path=displayPath(file.path);
    const source_url=path===file.path ? `https://github.com/${snapshot.repository}/blob/${snapshot.commit}/${file.path.split('/').map(encodeURIComponent).join('/')}` : null;
    files.push({path,blob_sha:file.blob_sha,content_sha256:file.content_sha256,bytes:file.bytes,source_url});
    const unique=new Set();
    for(const item of items) {
      const key=`${item.rule_id}:${item.line}`;
      if(unique.has(key)) continue; unique.add(key);
      const [severity,evidence,recommendation]=RULES[item.rule_id];
      findings.push({id:sha256(`${snapshot.repository}\n${snapshot.commit}\n${file.path}\n${key}`).slice(0,20),
        repository:snapshot.repository,commit:snapshot.commit,path,line:item.line,rule_id:item.rule_id,
        severity,confidence:item.confidence,classification:'STATIC_RISK_INDICATOR',
        evidence,recommendation,blob_sha:file.blob_sha,content_sha256:file.content_sha256,
        source_url:source_url?`${source_url}#L${item.line}`:null});
    }
  }
  for(const e of snapshot.exclusions) {
    requireAudit(validGitPath(e.path) && !paths.has(e.path) &&
      ['SYMLINK_NOT_FOLLOWED','SUBMODULE_NOT_FETCHED','BINARY_OR_NON_UTF8','LFS_OBJECT_NOT_FETCHED'].includes(e.reason),'INVALID_EXCLUSION');
    paths.add(e.path); gaps.push({path:displayPath(e.path),reason:e.reason});
  }
  const counts={HIGH:0,MEDIUM:0,LOW:0}; for(const f of findings) counts[f.severity]++;
  return {schema:'cyber_hak_auditshield_report_v0.2',repository:snapshot.repository,commit:snapshot.commit,
    tree_sha:snapshot.tree_sha,visibility:'public',acquisition:snapshot.transport,fetched_at:snapshot.fetched_at,
    status:gaps.length?'INCOMPLETE':'COMPLETE',verdict:gaps.length?'COVERAGE_GAPS':findings.length?'REVIEW_REQUIRED':'NO_INDICATORS_IN_SCOPE',
    coverage:{tree_files:snapshot.tree_file_count,scanned_text_files:files.length,
      scanned_bytes:files.reduce((n,f)=>n+f.bytes,0),gaps},counts,findings,files,
    execution:'NOT_RUN',release:'NOT_AUTHORIZED',limitations:[...LIMITATIONS]};
}
const escape = x => String(x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\|/g,'&#124;').replace(/`/g,'&#96;').replace(/[\r\n]/g,' ');
export function renderMarkdown(report) {
  const out=[`# AuditShield v0.2 — ${escape(report.repository)}`,'',
    `Revision: \`${report.commit}\``, `Status: **${report.status}** / **${report.verdict}**`,
    `Coverage: ${report.coverage.scanned_text_files}/${report.coverage.tree_files} text files; ${report.coverage.scanned_bytes} bytes.`,
    `Indicators: HIGH ${report.counts.HIGH}, MEDIUM ${report.counts.MEDIUM}, LOW ${report.counts.LOW}.`,'',
    'These are static risk indicators requiring review. No target code or discovered credential was executed or used.','',
    '| File / line | Rule | Risk | Evidence | Recommendation |','|---|---|---|---|---|'];
  for(const f of report.findings) out.push(`| ${escape(f.path)}:${f.line} | ${f.rule_id} | ${f.severity} | ${f.evidence} | ${f.recommendation} |`);
  if(!report.findings.length) out.push('| — | — | — | No configured indicators detected in scanned files. | This is not a security certification. |');
  out.push('','## Coverage gaps','');
  for(const g of report.coverage.gaps) out.push(`- ${escape(g.path)}: ${g.reason}`);
  if(!report.coverage.gaps.length) out.push('No acquisition or supported-parser gaps for this revision.');
  out.push('','## Limits','',...report.limitations.map(x=>'- '+x),'');
  return out.join('\n');
}
