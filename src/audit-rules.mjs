// Static indicators only: no credential validation, source execution or raw evidence excerpts.
export const RULES = Object.freeze({
  ANALYSIS_LIMIT:['MEDIUM','Per-file finding limit reached; further analysis is incomplete.','Review this file separately under bounded resources; do not treat this audit as complete.'],
  SECRET_TOKEN:['HIGH','Provider-shaped credential candidate detected; value withheld.','Privately verify ownership; revoke and rotate if real, then remove from tracked source and review history.'],
  SECRET_ASSIGNMENT:['MEDIUM','High-entropy literal assigned to a credential-like name; value withheld.','Review privately; load real credentials from an authorized secret store.'],
  PRIVATE_KEY:['HIGH','Private-key header, encoded body and footer occur together; material withheld.','Verify privately and rotate the key if real; remove private key material from the repository.'],
  SENSITIVE_FILE:['MEDIUM','Tracked filename indicates a credential or environment file.','Review its purpose and contents privately; retain only sanitized templates.'],
  SUSPICIOUS_FILE:['MEDIUM','Filename has an executable/binary extension or a disguised double extension.','Inspect provenance in an isolated review; do not execute the file.'],
  HIDDEN_UNICODE:['LOW','Bidirectional or zero-width hiding character occurs in source text.','Review the indicated line and remove unintended invisible characters.'],
  PATH_OBFUSCATION:['MEDIUM','Filename contains invisible or bidirectional control characters.','Review the path and rename deliberately after checking references.'],
  TLS_DISABLED:['HIGH','Configuration explicitly disables TLS certificate verification.','Enable certificate verification and configure the trusted CA correctly.'],
  PRIVILEGED_CONTAINER:['HIGH','Container configuration explicitly requests privileged execution or privilege escalation.','Remove elevated privileges and grant only the capabilities the workload needs.'],
  WORKFLOW_PARSE:['MEDIUM','Workflow is malformed or uses YAML features outside the supported strict subset; semantic checks incomplete.','Fix malformed YAML or review unsupported aliases/tags; rerun the audit.'],
  ACTION_UNPINNED:['MEDIUM','External action or reusable workflow uses a mutable or unrecognized reference.','Verify its upstream source and pin a full commit SHA (or image digest); review transitive dependencies.'],
  TOKEN_WRITE_ALL:['HIGH','Effective workflow token permission is write-all.','Declare the minimum per-job permissions; use read-only defaults.'],
  TOKEN_WRITE_SCOPE:['MEDIUM','Effective job permissions include a write scope.','Verify that this job needs writes and isolate it from untrusted inputs.'],
  TOKEN_PERMISSIONS_IMPLICIT:['MEDIUM','Effective job token permissions are inherited from an uninspected repository default.','Declare explicit least-privilege permissions in the workflow or each job.'],
  CHECKOUT_CREDENTIALS:['LOW','Checkout does not explicitly disable credential persistence.','Set persist-credentials: false unless a reviewed write operation requires it.'],
  PR_TARGET_UNTRUSTED_CHECKOUT:['HIGH','A pull_request_target workflow checks out a pull-request-controlled ref.','Keep privileged workflows on trusted source; run untrusted code in a separate unprivileged workflow.'],
  SCRIPT_INTERPOLATION:['HIGH','An untrusted GitHub expression is interpolated directly into executable script text.','Pass the value through an environment variable or structured input and quote its use.'],
  DOWNLOAD_EXECUTE:['HIGH','Script pipes a network download directly into a shell/interpreter.','Download for review, verify a pinned digest/signature, and execute only explicitly approved code.'],
  UNTRUSTED_SELF_HOSTED:['HIGH','A pull-request-triggered job targets a self-hosted runner.','Use isolated ephemeral runners and a reviewed trust policy before accepting untrusted contributions.']
});
const TOKENS = /\b(?:gsk_[A-Za-z0-9_-]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9_]{25,}|github_pat_[A-Za-z0-9_]{50,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,})\b/g;
const HIDDEN = /[\u200b\u200e\u200f\u202a-\u202e\u2060-\u206f]/u;
export const lineAt = (text, index) => text.slice(0,index).split('\n').length;
function placeholder(value) {
  return /^(?:example|placeholder|changeme|replace[-_]?me|your[-_]|test-only|dummy)(?:[-_A-Za-z0-9]*)$/i.test(value) ||
    /^(.)\1{7,}$/.test(value) || value === 'IOSFODNN7EXAMPLE';
}
function tokenIsPlaceholder(value) {
  return placeholder(value.replace(/^(?:gsk_|sk-(?:proj-|svcacct-)?|gh[pousr]_|github_pat_|AKIA|xox[baprs]-)/,''));
}
function entropy(value) {
  const counts = new Map();
  for(const c of value) counts.set(c,(counts.get(c)??0)+1);
  return [...counts.values()].reduce((n,c) => n - (c/value.length)*Math.log2(c/value.length),0);
}
export function displayPath(path) {
  // A filename itself can carry a secret. Never copy such a filename into a report URL.
  return path.replace(TOKENS,'[REDACTED]').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f]/gu,
    c => `\\u${c.charCodeAt(0).toString(16).padStart(4,'0')}`);
}
export function scanText({path,content}) {
  const findings=[];
  const add=(ruleId,line=1,confidence='MEDIUM')=>{if(findings.length<201)findings.push({rule_id:ruleId,line,confidence});};
  for(const match of content.matchAll(TOKENS)) {
    if(findings.length>=200) {add('ANALYSIS_LIMIT',1,'HIGH');return findings;}
    if(!tokenIsPlaceholder(match[0])) add('SECRET_TOKEN',lineAt(content,match.index),'HIGH');
  }
  const assignments=/\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key)\b["']?\s*[:=]\s*["']([A-Za-z0-9_+/=-]{20,200})["']/gi;
  for(const match of content.matchAll(assignments)) {
    if(findings.length>=200) {add('ANALYSIS_LIMIT',1,'HIGH');return findings;}
    if(!placeholder(match[1]) && entropy(match[1]) >= 3.5 && ![...match[1].matchAll(TOKENS)].length)
      add('SECRET_ASSIGNMENT',lineAt(content,match.index));
  }
  const pem=/-----BEGIN ((?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY)-----\s+[A-Za-z0-9+/=\r\n]{64,}\s*-----END \1-----/g;
  for(const match of content.matchAll(pem)) {
    if(findings.length>=200) {add('ANALYSIS_LIMIT',1,'HIGH');return findings;}
    add('PRIVATE_KEY',lineAt(content,match.index),'HIGH');
  }
  if(/(?:^|\/)(?:\.env(?:\.(?!(?:example|sample|template)$)[^/]+)?|id_rsa|id_ed25519|credentials|secrets\.json|wallet\.dat|seed\.txt)$|\.(?:p12|pfx|kdbx)$/i.test(path)) add('SENSITIVE_FILE');
  if(/\.(?:exe|dll|scr|com|msi|jar)$/i.test(path)) add('SUSPICIOUS_FILE');
  if(HIDDEN.test(path)) add('PATH_OBFUSCATION',1,'HIGH');
  const hidden=content.search(HIDDEN);
  if(hidden >= 0) add('HIDDEN_UNICODE',lineAt(content,hidden),'HIGH');
  // Parse configuration-specific literals only, not prose or commented examples.
  if(/(?:^|\/)(?:\.npmrc|\.gitconfig|pip\.conf)$/.test(path)) {
    for(const [i,line] of content.split('\n').entries()) {
      if(/^\s*[#;]/.test(line)) continue;
      if(/^\s*(?:strict-ssl|sslVerify)\s*=\s*false\s*(?:[#;].*)?$/i.test(line) || /^\s*trusted-host\s*=\s*\S+/.test(line)) add('TLS_DISABLED',i+1,'HIGH');
    }
  }
  return findings;
}
