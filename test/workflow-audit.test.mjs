import test from 'node:test';
import assert from 'node:assert/strict';
import {scanWorkflow,scanContainerConfig} from '../src/workflow-audit.mjs';
const pin='a'.repeat(40);
const base=`name: Test\non: [push, pull_request]\npermissions: {contents: read}\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@${pin}\n        with:\n          persist-credentials: false\n      - run: echo safe\n`;
const ids=s=>scanWorkflow(s).findings.map(f=>f.rule_id);
test('safe workflow passes including quoted on and comments with dangerous-looking examples',()=>{
  assert.deepEqual(ids(base+ '# permissions: write-all; curl example | bash\n'),[]);
  assert.deepEqual(ids(base.replace('on:','"on":')),[]);
});
test('unpinned action and persisted checkout credentials are separate actionable findings',()=>{
  const r=ids(base.replace(pin,'v4').replace('persist-credentials: false','persist-credentials: true'));
  assert.ok(r.includes('ACTION_UNPINNED')); assert.ok(r.includes('CHECKOUT_CREDENTIALS'));
});
test('missing token permissions, global writes and job overrides are correctly interpreted',()=>{
  assert.ok(ids(base.replace('permissions: {contents: read}\n','')).includes('TOKEN_PERMISSIONS_IMPLICIT'));
  assert.ok(ids(base.replace('{contents: read}','write-all')).includes('TOKEN_WRITE_ALL'));
  assert.ok(ids(base.replace('{contents: read}','{contents: write}')).includes('TOKEN_WRITE_SCOPE'));
  assert.deepEqual(ids(base.replace('{contents: read}','write-all').replace('    runs-on:','    permissions: {}\n    runs-on:')),[]);
  assert.deepEqual(ids(base.replace('permissions: {contents: read}\n','').replace('    runs-on:','    permissions: {contents: read}\n    runs-on:')),[]);
});
test('direct untrusted script interpolation is flagged; env data flow avoids that indicator',()=>{
  const expr='${{ github.event.pull_request.title }}';
  assert.ok(ids(base.replace('echo safe','echo "'+expr+'"')).includes('SCRIPT_INTERPOLATION'));
  assert.deepEqual(ids(base.replace('      - run: echo safe','      - env:\n          TITLE: '+expr+'\n        run: echo "$TITLE"')),[]);
});
test('untrusted checkout under pull_request_target is flagged, metadata-only workflow is not',()=>{
  const w=base.replace('[push, pull_request]','pull_request_target');
  assert.deepEqual(ids(w),[]);
  assert.ok(ids(w.replace('persist-credentials: false','persist-credentials: false\n          ref: ${{ github.event.pull_request.head.sha }}')).includes('PR_TARGET_UNTRUSTED_CHECKOUT'));
});
test('download-to-shell and untrusted self-hosted runner are detected',()=>{
  assert.ok(ids(base.replace('echo safe','curl https://example.invalid/install | bash')).includes('DOWNLOAD_EXECUTE'));
  assert.ok(ids(base.replace('ubuntu-latest','[self-hosted, linux]')).includes('UNTRUSTED_SELF_HOSTED'));
});
test('reusable workflows and Docker actions require immutable refs, local actions do not',()=>{
  for(const ref of ['owner/repo/.github/workflows/build.yml@main','docker://alpine:latest'])
    assert.ok(ids(base.replace('actions/checkout@'+pin,ref)).includes('ACTION_UNPINNED'));
  for(const ref of ['./actions/local','docker://alpine@sha256:'+'a'.repeat(64)])
    assert.deepEqual(ids(base.replace('actions/checkout@'+pin,ref)),[]);
});
test('malformed YAML, duplicate keys, aliases and unknown tags cause incomplete semantic coverage',()=>{
  for(const input of ['jobs: [','on: push\non: pull_request\njobs: {}','x: &a [x]\ny: *a','!!evil secret','name: no jobs']) {
    const r=scanWorkflow(input); assert.equal(r.complete,false); assert.equal(r.findings[0].rule_id,'WORKFLOW_PARSE');
    assert.equal(JSON.stringify(r).includes('secret'),false);
  }
});
test('steps with malicious names do not leak names in evidence',()=>{
  const r=scanWorkflow(base.replace('      - run: echo safe','      - name: SENSITIVE-EXAMPLE\n        run: echo "${{ github.head_ref }}"'));
  assert.equal(JSON.stringify(r).includes('SENSITIVE-EXAMPLE'),false);
});
test('container privileges are parsed, comments and false values do not alert',()=>{
  assert.equal(scanContainerConfig('services:\n  app:\n    privileged: true').findings[0].rule_id,'PRIVILEGED_CONTAINER');
  assert.deepEqual(scanContainerConfig('# privileged: true\nservices:\n  app:\n    privileged: false').findings,[]);
});
test('trusted numeric/event contexts and quoted command examples do not trigger injection or download rules',()=>{
  for(const script of ['echo "${{ github.event_name }}"','echo "${{ github.event.pull_request.number }}"','echo "curl example | bash"','# curl example | bash'])
    assert.deepEqual(ids(base.replace('echo safe','|\n          '+script)),[]);
});
test('bracketed untrusted context and TLS-disabled step environment are detected',()=>{
  assert.ok(ids(base.replace('echo safe',`echo "\${{ github['event']['issue']['title'] }}"`)).includes('SCRIPT_INTERPOLATION'));
  assert.ok(ids(base.replace('      - run: echo safe','      - run: echo safe\n        env:\n          NODE_TLS_REJECT_UNAUTHORIZED: 0')).includes('TLS_DISABLED'));
});
test('YAML mapping keys cannot pollute object prototypes or grant inherited permissions',()=>{
  const input=base.replace('permissions: {contents: read}','__proto__: {permissions: write-all}');
  assert.ok(ids(input).includes('TOKEN_PERMISSIONS_IMPLICIT'));assert.equal(({}).permissions,undefined);
});
