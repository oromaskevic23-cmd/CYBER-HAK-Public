/**
 * CYBER HAK offline security gate tests.
 * Founding Architect: Alexander Nikolaevich Romaskevich (RomaskevicH).
 * Original implementation contributors: see Git history and AUTHORS.md.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {scanText,scanRepository,main} from '../tools/source-security-gate.mjs';

function repoFixture(fn) {
  const root=mkdtempSync(join(tmpdir(),'cyber-hak-security-gate-test-'));
  const git=(...args)=>execFileSync('git',['-C',root,...args],{
    encoding:'utf8',env:{PATH:process.env.PATH||'/usr/bin:/bin',
      HOME:root,GIT_CONFIG_NOSYSTEM:'1',GIT_AUTHOR_NAME:'Test',
      GIT_AUTHOR_EMAIL:'test@example.invalid',GIT_COMMITTER_NAME:'Test',
      GIT_COMMITTER_EMAIL:'test@example.invalid'} }).trim();
  const put=(p,src)=>{
    const parts=p.split('/'); if(parts.length>1)
      mkdirSync(join(root,...parts.slice(0,-1)),{recursive:true});
    writeFileSync(join(root,...parts),src);
  };
  try {
    git('init','-q');git('config','user.name','Test');
    git('config','user.email','test@example.invalid');
    put('src/app.js','export const safe = 1;\n');
    put('.github/workflows/ci.yml','name: safe\njobs:\n  scan:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n');
    git('add','.');git('commit','-qm','safe baseline');
    return fn({root,git,put});
  }finally{rmSync(root,{recursive:true,force:true})}
}
test('deterministic clean baseline: matches no policy indicators, not comprehensive security',()=>{
  repoFixture(({root})=>{
    const r=scanRepository({root});
    assert.equal(r.policy_signals,0);
    assert.equal(r.scanned_files,2);
    assert.equal(r.result,'NO_SIGNALS_IN_LIMITED_STATIC_RULESET');
    assert.equal(r.coverage_complete,false);
    assert.equal(r.independent_qa_verified,false);
    assert.equal(r.production_authorized,false);
    assert.equal(scanRepository({root}).report_sha256,r.report_sha256);
  });
});
test('unpinned action, write-all, remote script, pull_request_target flagged by line',()=>{
  const lines=['permissions: write-all','pull_request_target:',
    '  - uses: actions/checkout@v4','  run: curl https://example.invalid/script | bash'].join('\n');
  const result=scanText('.github/workflows/unsafe.yml',lines);
  assert.deepEqual(result.map(x=>x.rule_id),[
    'CHAK-CI-001','CHAK-CI-003','CHAK-CI-002','CHAK-CI-004'
  ]);
  assert.ok(result.every(x=>x.classification==='STATIC_POLICY_SIGNAL' &&
    x.validated_exploit===false && !JSON.stringify(x).includes('https://example.invalid')));
});
test('private-key and PAT patterns found with no secret value in evidence',()=>{
  const secret='-----'+'BEGIN PRIVATE KEY-----';
  const credential='ghp_'+'A'.repeat(40);
  const signals=scanText('src/secret.txt',secret+'\n'+credential);
  assert.deepEqual(signals.map(x=>x.rule_id),['CHAK-SECRET-001','CHAK-SECRET-002']);
  assert.ok(!JSON.stringify(signals).includes(credential));
  assert.ok(!JSON.stringify(signals).includes(secret));
});
test('full scan detects deliberate compromised tracked sources',()=>{
  repoFixture(({root,git,put})=>{
    put('.github/workflows/ci.yml','name: bad\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n');
    git('add','.');git('commit','-qm','bad workflow');
    const result=scanRepository({root});
    assert.equal(result.policy_signals,1);
    assert.equal(result.findings[0].rule_id,'CHAK-CI-002');
    assert.equal(result.source_commit,git('rev-parse','HEAD'));
  });
});
test('changed-only scope rejects introduced policy violations but not baseline',()=>{
  repoFixture(({root,git,put})=>{
    put('src/legacy.js','export const x=2;\n');
    git('add','.');git('commit','-qm','add legacy');
    const base=git('rev-parse','HEAD');
    put('src/new.js','export const y=3;\n');
    put('.github/workflows/new.yml','name: new\njobs:\n  t:\n    steps:\n      - uses: actions/setup-node@v4\n');
    git('add','.');git('commit','-qm','bad newly introduced action');
    const result=scanRepository({root,base});
    assert.equal(result.scope,'TRACKED_SOURCE_CHANGED_ONLY');
    assert.equal(result.policy_signals,1);
    assert.deepEqual(result.findings.map(x=>x.path),['.github/workflows/new.yml']);
  });
});
test('one untracked malicious file is not silently presented as reviewed',()=>{
  repoFixture(({root,put})=>{
    put('.github/workflows/untracked.yml','permissions: write-all\n');
    const r=scanRepository({root});
    assert.equal(r.policy_signals,0);
    assert.equal(r.scope,'TRACKED_SOURCE_FULL');
    assert.equal(r.coverage_complete,false);
  });
});
test('symlinked tracked source denied rather than followed',()=>{
  repoFixture(({root,git})=>{
    const {symlinkSync}=requireless();
    symlinkSync('/etc/passwd',join(root,'src/unsafe.js'));
    git('add','.');git('commit','-qm','add symlink');
    assert.throws(()=>scanRepository({root}),/UNSAFE_TRACKED_SOURCE_OR_SIZE/);
  });
});
function requireless(){return {symlinkSync:(...args)=>_symlinkSync(...args)}}
import {symlinkSync as _symlinkSync} from 'node:fs';
test('invalid base commit fails closed',()=>{
  repoFixture(({root})=>{
    assert.throws(()=>scanRepository({root,base:'a'}),/EXACT_BASE_COMMIT_REQUIRED/);
  });
});
test('enforced CLI has exit 3, produces private JSON only outside target',()=>{
  repoFixture(({root,git,put})=>{
    put('.github/workflows/test.yml','jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n');
    git('add','.');git('commit','-qm','bad');
    const tmp=mkdtempSync(join(tmpdir(),'security-gate-output-'));
    try{
      const f=join(tmp,'report.json');
      const code=main(['--root',root,'--report',f,'--enforce']);
      assert.equal(code,3);
      const report=JSON.parse(readFileSync(f,'utf8'));
      assert.equal(report.policy_signals,1);
      assert.equal(report.coverage_complete,false);
      assert.equal(report.production_authorized,false);
    }finally{rmSync(tmp,{recursive:true,force:true})}
  });
});
test('unknown CLI arguments rejected',()=>{
  assert.throws(()=>main(['--bad']),/UNKNOWN_OR_INCOMPLETE_ARGUMENT/);
});
