// AuditShield v0.2: bounded anonymous GET-only public GitHub reader. Never executes source.
import {createHash} from 'node:crypto';

export const SHA = /^[a-f0-9]{40}$/;
const REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/;
const MAX_FILES = 500;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const gitBlobSha = bytes => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
export function requireAudit(value, code) { if (!value) throw new Error(code); }

export function authorizeTarget(target, allowedTargets) {
  requireAudit(target && REPO.test(target.repository ?? '') &&
    !['.','..'].includes(target.repository.split('/')[1]) && SHA.test(target.commit ?? ''), 'INVALID_TARGET');
  requireAudit(Array.isArray(allowedTargets) && allowedTargets.some(t =>
    t.repository === target.repository && t.commit === target.commit), 'TARGET_NOT_AUTHORIZED');
}

export function validGitPath(path) {
  return typeof path === 'string' && path.length > 0 && path.length <= 1024 &&
    !path.includes('\\') && !path.includes('\0') &&
    path.split('/').every(s => s && s !== '.' && s !== '..' && s.toLowerCase() !== '.git');
}

async function getBytes(url, maxBytes, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(url, {method:'GET', redirect:'error', credentials:'omit',
      headers:{Accept:'application/vnd.github+json', 'User-Agent':'CYBER-HAK-AuditShield/0.2'},
      signal:AbortSignal.timeout(12000)});
  } catch { throw new Error('GITHUB_TRANSPORT_FAILED'); }
  requireAudit(response.status === 200, response.status === 403 || response.status === 429 ?
    'GITHUB_RATE_OR_ACCESS_DENIED' : 'GITHUB_READ_FAILED');
  const length = response.headers.get('content-length');
  requireAudit(length === null || (/^\d+$/.test(length) && Number(length) <= maxBytes), 'RESPONSE_SIZE_LIMIT');
  requireAudit(response.body, 'RESPONSE_BODY_MISSING');
  const chunks = []; let count = 0;
  try {
    for await (const chunk of response.body) {
      count += chunk.length;
      requireAudit(count <= maxBytes, 'RESPONSE_SIZE_LIMIT');
      chunks.push(chunk);
    }
  } catch (error) { throw new Error(error.message === 'RESPONSE_SIZE_LIMIT' ? 'RESPONSE_SIZE_LIMIT' : 'RESPONSE_STREAM_FAILED'); }
  return Buffer.concat(chunks);
}

// fetchImpl is an explicit test seam, never chosen by scanned repository data.
export async function readGitHubRepository(target, {allowedTargets = [], fetchImpl = globalThis.fetch} = {}) {
  authorizeTarget(target, allowedTargets);
  const {repository, commit} = target;
  const api = `https://api.github.com/repos/${repository}`;
  const json = async path => {
    const bytes = await getBytes(api + path, 2 * 1024 * 1024, fetchImpl);
    try { return JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes)); }
    catch { throw new Error('INVALID_GITHUB_JSON'); }
  };
  const metadata = await json('');
  requireAudit(metadata.full_name?.toLowerCase() === repository.toLowerCase() && metadata.private === false, 'PUBLIC_REPOSITORY_REQUIRED');
  const revision = await json(`/git/commits/${commit}`);
  requireAudit(revision.sha === commit && SHA.test(revision.tree?.sha ?? ''), 'COMMIT_MISMATCH');
  const tree = await json(`/git/trees/${revision.tree.sha}?recursive=1`);
  requireAudit(tree.sha === revision.tree.sha && tree.truncated === false && Array.isArray(tree.tree), 'INCOMPLETE_GIT_TREE');
  requireAudit(tree.tree.length <= MAX_FILES * 4, 'TREE_SIZE_LIMIT');
  const entries = tree.tree.filter(e => e.type !== 'tree');
  requireAudit(entries.length <= MAX_FILES, 'FILE_COUNT_LIMIT');
  const names = new Set(); let declaredBytes = 0;
  for (const e of entries) {
    requireAudit(validGitPath(e.path) && !names.has(e.path) && SHA.test(e.sha ?? ''), 'INVALID_TREE_ENTRY');
    names.add(e.path);
    requireAudit(['100644','100755','120000','160000'].includes(e.mode) &&
      ((e.type === 'blob' && e.mode !== '160000') || (e.type === 'commit' && e.mode === '160000')), 'UNSUPPORTED_TREE_ENTRY');
    if (e.type === 'blob') {
      requireAudit(Number.isSafeInteger(e.size) && e.size >= 0 && e.size <= MAX_FILE_BYTES, 'FILE_SIZE_LIMIT');
      declaredBytes += e.size;
    }
  }
  requireAudit(declaredBytes <= MAX_TOTAL_BYTES, 'TOTAL_SIZE_LIMIT');
  const files = [], exclusions = [];
  for (const e of entries) {
    if (e.mode === '120000' || e.mode === '160000') {
      exclusions.push({path:e.path, reason:e.mode === '120000' ? 'SYMLINK_NOT_FOLLOWED' : 'SUBMODULE_NOT_FETCHED'});
      continue;
    }
    // No Authorization header is ever sent to raw.githubusercontent.com (or any host).
    const path = e.path.split('/').map(encodeURIComponent).join('/');
    const bytes = await getBytes(`https://raw.githubusercontent.com/${repository}/${commit}/${path}`, MAX_FILE_BYTES, fetchImpl);
    requireAudit(bytes.length === e.size && gitBlobSha(bytes) === e.sha, 'BLOB_INTEGRITY_MISMATCH');
    let content;
    try { content = new TextDecoder('utf-8', {fatal:true, ignoreBOM:true}).decode(bytes); }
    catch { exclusions.push({path:e.path, reason:'BINARY_OR_NON_UTF8'}); continue; }
    if (content.includes('\0')) { exclusions.push({path:e.path, reason:'BINARY_OR_NON_UTF8'}); continue; }
    if (content.startsWith('version https://git-lfs.github.com/spec/v1\n')) {
      exclusions.push({path:e.path, reason:'LFS_OBJECT_NOT_FETCHED'}); continue;
    }
    files.push({path:e.path, content, blob_sha:e.sha, content_sha256:sha256(bytes), bytes:bytes.length, mode:e.mode});
  }
  return {repository, commit, tree_sha:tree.sha, transport:'LIVE_ANONYMOUS_GITHUB_GET',
    fetched_at:new Date().toISOString(), visibility:'public', files, exclusions,
    tree_file_count:entries.length, scanned_bytes:files.reduce((n,f) => n + f.bytes, 0)};
}
