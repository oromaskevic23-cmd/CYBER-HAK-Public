// CYBER HAK v0.1 — Public Defensive Artifact Guard. Read-only inspection; no execution.
import {createHash} from "node:crypto";
const MAX_BYTES = 256 * 1024;
const MAX_PATH = 240;
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
const SECRETS = [
  {code:"PRIVATE_KEY_MATERIAL",re:/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/},
  {code:"GROQ_API_KEY",re:/gsk_[A-Za-z0-9_-]{20,}/},
  {code:"OPENAI_API_KEY",re:/sk-(?:proj-)?[A-Za-z0-9_-]{24,}/},
  {code:"AWS_ACCESS_KEY",re:/AKIA[0-9A-Z]{16}/},
  {code:"GITHUB_TOKEN",re:/(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{25,}/}
];
const TEXT_FORBIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
const BLOCK_NAMES = new Set([
  ".env",".env.local",".env.production",".npmrc",".pypirc",".netrc",".git",
  "id_rsa","id_ed25519","authorized_keys","known_hosts","credentials",
  "secrets.json","wallet.dat","keystore","seed.txt"
]);
const EXT_BLOCK = /\.(?:pem|p12|pfx|key|asc|kdbx)$/i;

export function inspectArtifact({path, content, classification="PUBLIC"}={}) {
  const reasons=[];
  if(classification!=="PUBLIC")reasons.push("NON_PUBLIC_CLASSIFICATION");
  if(typeof path!=="string"||!path||path.length>MAX_PATH||CONTROL.test(path)||
     path.includes("\\")||path.startsWith("/")||/^[A-Za-z]:/.test(path)||
     path.includes("%")||path.includes("//"))reasons.push("INVALID_ARTIFACT_PATH");
  else {
    const segments=path.split("/");
    if(segments.some(s=>!s||s==="."||s===".."||s.startsWith(".")||
      BLOCK_NAMES.has(s.toLowerCase())||/[\s:]|[^A-Za-z0-9_.-]/.test(s)))
      reasons.push("UNSAFE_ARTIFACT_PATH");
    if(segments.some(s=>EXT_BLOCK.test(s)))reasons.push("SENSITIVE_FILE_EXTENSION");
  }
  if(typeof content!=="string")reasons.push("INVALID_CONTENT_TYPE");
  else {
    const bytes=Buffer.byteLength(content,"utf8");
    if(bytes>MAX_BYTES)reasons.push("CONTENT_SIZE_LIMIT");
    if(TEXT_FORBIDDEN.test(content))reasons.push("HIDDEN_OR_CONTROL_CHARACTERS");
    for(const secret of SECRETS)if(secret.re.test(content))reasons.push(secret.code);
  }
  const unique=[...new Set(reasons)];
  const sha256=typeof content==="string"?createHash("sha256").update(content,"utf8").digest("hex"):null;
  return Object.freeze({decision:unique.length?"DENY":"REVIEW_ONLY",reasons:unique,
    content_sha256:sha256,checks:"HEURISTIC_ONLY_NOT_SANDBOX",authority:"NONE",
    execution:"NOT_RUN",release:"DENIED"});
}

// Returns no raw secret-bearing content. A REVIEW_ONLY artifact is not authorized for publication.
