import test from 'node:test';
import assert from 'node:assert/strict';
import {readGitHubRepository, gitBlobSha, validGitPath} from '../src/github-reader.mjs';

const target = {repository:'owner/approved', commit:'a'.repeat(40)};
const treeSha = 'b'.repeat(40);
function mock({content='safe\n', entry={}, tree={}, metadata={}, revision={}, response} = {}) {
  const bytes = Buffer.from(content), calls = [];
  const file = {path:'.github/workflows/ci.yml', type:'blob', mode:'100644', size:bytes.length, sha:gitBlobSha(bytes), ...entry};
  return {calls, fetchImpl:async (url, options) => {
    calls.push({url,options});
    if (response) return response(url);
    if (url.includes('raw.githubusercontent.com')) return new Response(bytes);
    if (url.includes('/git/trees/')) return Response.json({sha:treeSha,truncated:false,tree:[file],...tree});
    if (url.includes('/git/commits/')) return Response.json({sha:target.commit,tree:{sha:treeSha},...revision});
    return Response.json({full_name:target.repository,private:false,...metadata});
  }};
}
const read = m => readGitHubRepository(target, {allowedTargets:[target],fetchImpl:m.fetchImpl});
test('authorized immutable public source is verified, hidden workflows are included, only GET is used', async () => {
  const m = mock(), s = await read(m);
  assert.equal(s.files[0].path,'.github/workflows/ci.yml');
  assert.equal(s.files[0].content,'safe\n');
  assert.equal(s.exclusions.length,0);
  assert.equal(m.calls.length,4);
  for (const {url,options} of m.calls) {
    assert.ok(url.startsWith('https://api.github.com/') || url.startsWith('https://raw.githubusercontent.com/'));
    assert.equal(options.method,'GET'); assert.equal(options.redirect,'error');
    assert.equal(options.credentials,'omit'); assert.equal(options.headers.Authorization,undefined);
  }
});
test('unauthorized repository or revision fails before network access', async () => {
  const m = mock();
  await assert.rejects(readGitHubRepository(target,{fetchImpl:m.fetchImpl}),/TARGET_NOT_AUTHORIZED/);
  await assert.rejects(readGitHubRepository({...target,commit:'main'},{allowedTargets:[target],fetchImpl:m.fetchImpl}),/INVALID_TARGET/);
  assert.equal(m.calls.length,0);
});
test('repository dot segments cannot change the fixed API path even if listed in scope',async()=>{
  const m=mock();
  for(const repository of ['owner/.','owner/..']) {
    const t={...target,repository};
    await assert.rejects(readGitHubRepository(t,{allowedTargets:[t],fetchImpl:m.fetchImpl}),/INVALID_TARGET/);
  }
  assert.equal(m.calls.length,0);
});
test('private repository rejected even if allowlisted', async () => {
  const m=mock({metadata:{private:true}}); await assert.rejects(read(m),/PUBLIC_REPOSITORY_REQUIRED/);
  assert.equal(m.calls.length,1);
});
for (const [name, options, code] of [
  ['commit substitution',{revision:{sha:'c'.repeat(40)}},'COMMIT_MISMATCH'],
  ['truncated tree',{tree:{truncated:true}},'INCOMPLETE_GIT_TREE'],
  ['tree substitution',{tree:{sha:'c'.repeat(40)}},'INCOMPLETE_GIT_TREE'],
  ['traversal',{entry:{path:'../x'}},'INVALID_TREE_ENTRY'],
  ['oversized file',{entry:{size:262145}},'FILE_SIZE_LIMIT'],
  ['tampered content',{entry:{sha:'c'.repeat(40)}},'BLOB_INTEGRITY_MISMATCH'],
]) test(name+' fails closed', async () => assert.rejects(read(mock(options)),new RegExp(code)));
test('symlinks and submodules are explicit coverage gaps and never followed', async () => {
  const m=mock({entry:{mode:'120000'}}), s=await read(m);
  assert.equal(s.files.length,0); assert.equal(s.exclusions[0].reason,'SYMLINK_NOT_FOLLOWED'); assert.equal(m.calls.length,3);
});
test('binary and LFS contents are not reported as scanned', async () => {
  for(const content of ['\0x','version https://git-lfs.github.com/spec/v1\noid sha256:abc']) {
    const s=await read(mock({content})); assert.equal(s.files.length,0); assert.equal(s.exclusions.length,1);
  }
});
test('response errors and transport failures contain no response body or secrets', async () => {
  await assert.rejects(read(mock({response:()=>new Response('secret material',{status:403})})),/^Error: GITHUB_RATE_OR_ACCESS_DENIED$/);
  await assert.rejects(read({fetchImpl:()=>{throw new Error('private material');}}),/^Error: GITHUB_TRANSPORT_FAILED$/);
});
test('path validator permits dotfiles but rejects traversal and Git internals', () => {
  assert.equal(validGitPath('.github/workflows/ci.yml'),true);
  for(const path of ['/root','a/../b','.git/config','x\\y','a//b']) assert.equal(validGitPath(path),false);
});
test('BOM and Unicode byte lengths are preserved for Git integrity verification',async()=>{
  const content='\ufeffПривет 👩‍💻'; const s=await read(mock({content}));
  assert.equal(s.files[0].content,content); assert.equal(s.files[0].bytes,Buffer.byteLength(content));
});
test('duplicate paths and too many entries are rejected before raw reads',async()=>{
  const e={path:'a',type:'blob',mode:'100644',size:0,sha:gitBlobSha(Buffer.alloc(0))};
  await assert.rejects(read(mock({tree:{tree:[e,e]}})),/INVALID_TREE_ENTRY/);
  await assert.rejects(read(mock({tree:{tree:Array.from({length:501},(_,i)=>({...e,path:'x'+i}))}})),/FILE_COUNT_LIMIT/);
});
test('redirect responses are rejected and never followed by the reader',async()=>{
  const m=mock({response:()=>new Response(null,{status:302,headers:{location:'https://example.invalid/'}})});
  await assert.rejects(read(m),/GITHUB_READ_FAILED/);assert.equal(m.calls.length,1);
});
test('oversized response without content-length is bounded while streaming',async()=>{
  const m=mock({response:()=>new Response('x'.repeat(2*1024*1024+1))});
  await assert.rejects(read(m),/RESPONSE_SIZE_LIMIT/);
});
test('malformed JSON error never includes the body',async()=>{
  await assert.rejects(read(mock({response:()=>new Response('PRIVATE_ERROR_BODY')})),/^Error: INVALID_GITHUB_JSON$/);
});
test('submodules do not cause requests to another repository',async()=>{
  const m=mock({entry:{mode:'160000',type:'commit',size:undefined}}),s=await read(m);
  assert.equal(s.exclusions[0].reason,'SUBMODULE_NOT_FETCHED');assert.equal(m.calls.length,3);
});
