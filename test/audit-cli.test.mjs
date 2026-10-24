import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const cli=new URL('../tools/audit-github.mjs',import.meta.url).pathname;
test('CLI help states the distinction between complete audit and no findings',()=>{
  const r=spawnSync(process.execPath,[cli,'--help'],{encoding:'utf8'});
  assert.equal(r.status,0); assert.match(r.stdout,/may contain findings/);
});
test('invalid invocation does not echo user-supplied content',()=>{
  const r=spawnSync(process.execPath,[cli,'--unrecognized-private-data'],{encoding:'utf8'});
  assert.equal(r.status,2); assert.equal(r.stderr.includes('unrecognized-private-data'),false);
});
test('unauthorized malformed target fails before network, records incomplete and redacts target input',()=>{
  const dir=mkdtempSync(join(tmpdir(),'auditshield-cli-'));
  try {
    writeFileSync(join(dir,'targets.json'),JSON.stringify({targets:[{repository:'PRIVATE_INPUT',commit:'bad'}]}));
    const r=spawnSync(process.execPath,[cli,'--targets',join(dir,'targets.json'),'--out',join(dir,'out')],{encoding:'utf8'});
    assert.equal(r.status,2);assert.equal((r.stdout+r.stderr).includes('PRIVATE_INPUT'),false);
    const summary=readFileSync(join(dir,'out','summary.json'),'utf8');
    assert.equal(summary.includes('PRIVATE_INPUT'),false);assert.equal(JSON.parse(summary).status,'INCOMPLETE');
  } finally {rmSync(dir,{recursive:true,force:true});}
});
