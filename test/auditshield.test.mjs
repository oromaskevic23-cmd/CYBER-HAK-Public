import test from 'node:test';
import assert from 'node:assert/strict';
import {auditSnapshot,renderMarkdown} from '../src/auditshield.mjs';
import {gitBlobSha,sha256} from '../src/github-reader.mjs';
const target={repository:'owner/approved',commit:'a'.repeat(40)};
function snapshot(content='hello',path='README.md') {
  const bytes=Buffer.from(content);
  return {...target,tree_sha:'b'.repeat(40),transport:'TEST_FIXTURE',fetched_at:'2026-01-01T00:00:00Z',tree_file_count:1,exclusions:[],
    files:[{path,content,bytes:bytes.length,blob_sha:gitBlobSha(bytes),content_sha256:sha256(bytes)}]};
}
const audit=s=>auditSnapshot(s,{allowedTargets:[target]});
test('report binds exact revision and content receipts without embedding source',()=>{
  const r=audit(snapshot('safe text'));
  assert.equal(r.commit,target.commit);assert.equal(r.status,'COMPLETE');assert.equal(r.verdict,'NO_INDICATORS_IN_SCOPE');
  assert.equal(JSON.stringify(r).includes('safe text'),false);assert.equal(r.release,'NOT_AUTHORIZED');
});
test('report includes file, line, severity, constant evidence and remediation for a real indicator',()=>{
  const r=audit(snapshot('strict-ssl=false','.npmrc'));
  assert.equal(r.findings[0].path,'.npmrc');assert.equal(r.counts.HIGH,1);assert.equal(r.status,'COMPLETE');
  assert.equal(r.verdict,'REVIEW_REQUIRED');assert.ok(renderMarkdown(r).includes('TLS_DISABLED'));
});
test('no raw secret or secret-bearing filename survives JSON or Markdown reporting',()=>{
  const secret='ghp_'+Array.from({length:36},(_,i)=>String.fromCharCode(65+(i*7)%26)).join('');
  const r=audit(snapshot(secret,secret+'.txt'));
  assert.equal(r.findings[0].source_url,null);
  assert.equal(JSON.stringify(r).includes(secret),false);assert.equal(renderMarkdown(r).includes(secret),false);
});
test('missing files, duplicate paths and altered snapshots cannot yield clean evidence',()=>{
  const s=snapshot();s.files[0].content='tampered';assert.throws(()=>audit(s),/SNAPSHOT_INTEGRITY/);
  const missing=snapshot();missing.tree_file_count=2;assert.throws(()=>audit(missing),/INVALID_SNAPSHOT/);
  const dup=snapshot();dup.files.push(dup.files[0]);dup.tree_file_count=2;assert.throws(()=>audit(dup),/INVALID_SNAPSHOT_FILE/);
});
test('unparsed workflow and excluded binary both cause incomplete coverage',()=>{
  assert.equal(audit(snapshot('jobs: [','.github/workflows/ci.yml')).status,'INCOMPLETE');
  const s=snapshot();s.tree_file_count++;s.exclusions.push({path:'sample.bin',reason:'BINARY_OR_NON_UTF8'});
  assert.equal(audit(s).status,'INCOMPLETE');
});
test('Markdown does not interpret hostile filenames as markup',()=>{
  const md=renderMarkdown(audit(snapshot('strict-ssl=false','<tag>|`x`.env')));
  assert.equal(md.includes('<tag>'),false);
});
