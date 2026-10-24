import test from 'node:test';
import assert from 'node:assert/strict';
import {scanText,displayPath,RULES} from '../src/audit-rules.mjs';
const synthetic='gsk_'+Array.from({length:32},(_,i)=>String.fromCharCode(65+(i*7)%26)).join('');
const scan=(content,path='config.txt')=>scanText({path,content});
test('credential candidate has line and static evidence metadata, never the value',()=>{
  const r=scan('intro\nkey='+synthetic);
  assert.equal(r[0].rule_id,'SECRET_TOKEN'); assert.equal(r[0].line,2);
  assert.equal(JSON.stringify(r).includes(synthetic),false);
});
test('actual candidate in a test file or example comment is still reported',()=>{
  assert.equal(scan('# example '+synthetic,'test/example.js')[0].rule_id,'SECRET_TOKEN');
});
test('short placeholders, repeated fake token suffixes and environment references do not alert',()=>{
  for(const s of ['gsk_example','ghp_'+'A'.repeat(40),'API_KEY=process.env.API_KEY',"password='test-only-fake-password-12345'"])
    assert.deepEqual(scan(s),[]);
});
test('generic high-entropy assignments alert without treating public hashes as credentials',()=>{
  assert.equal(scan('api_key="a8Gs6Lz92PaR3dY1B7qC5tUw"')[0].rule_id,'SECRET_ASSIGNMENT');
  assert.deepEqual(scan('sha256="a8Gs6Lz92PaR3dY1B7qC5tUw"'),[]);
});
test('PEM detection requires a full encoded block, not a marker mentioned in docs or tests',()=>{
  const header='-----BEGIN PRIVATE KEY-----', footer='-----END PRIVATE KEY-----';
  assert.deepEqual(scan(header+'\nNOT-A-KEY'),[]);
  assert.equal(scan(header+'\n'+'ABc1'.repeat(24)+'\n'+footer)[0].rule_id,'PRIVATE_KEY');
});
test('real env file is flagged while sanitized template and dotfile workflow paths are legitimate',()=>{
  assert.equal(scan('','sub/.env.production')[0].rule_id,'SENSITIVE_FILE');
  assert.deepEqual(scan('','.env.example'),[]); assert.deepEqual(scan('','.github/workflows/ci.yml'),[]);
});
test('Unicode checks allow ordinary Cyrillic and emoji, but identify hidden bidirectional characters',()=>{
  assert.deepEqual(scan('Привет 👩‍💻'),[]);
  assert.equal(scan('a\n\u202eb')[0].line,2);
  assert.equal(scan('safe','docs/\u200bfile.md')[0].rule_id,'PATH_OBFUSCATION');
});
test('TLS checks are config-aware and do not flag documentation or comments',()=>{
  assert.equal(scan('strict-ssl=false','.npmrc')[0].rule_id,'TLS_DISABLED');
  assert.deepEqual(scan('# strict-ssl=false','.npmrc'),[]);
  assert.deepEqual(scan('strict-ssl=false','README.md'),[]);
});
test('secret-shaped filenames are redacted too',()=>{
  assert.equal(displayPath('dir/'+synthetic+'.txt'),'dir/[REDACTED].txt');
});
test('every rule provides severity, constant evidence and an actionable recommendation',()=>{
  for(const [,r] of Object.entries(RULES)) { assert.equal(r.length,3); assert.ok(['LOW','MEDIUM','HIGH'].includes(r[0])); }
});
test('dense credential-like input reaches an explicit finding limit',()=>{
  const r=scan((synthetic+'\n').repeat(210));
  assert.equal(r.length,201);assert.equal(r.at(-1).rule_id,'ANALYSIS_LIMIT');
});
