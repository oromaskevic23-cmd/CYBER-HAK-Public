import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const input=JSON.parse(readFileSync(new URL('../config/audit-targets.json',import.meta.url),'utf8'));
const revised='2f46032fc7f0cb22032ce503109667f98c847f2f';
test('Sprint 003 audits original immutable controls alongside amended reference',()=>{
 assert.equal(input.targets.length,4);
 assert.deepEqual(new Set(input.targets.map(v=>v.repository)).size,3);
 assert.equal(input.targets.filter(v=>v.repository.endsWith('CONSTRUCTOR-AI')).length,2);
 assert.ok(input.targets.some(v=>v.commit===revised));
 for(const t of input.targets) {
  assert.match(t.repository,/^oromaskevic23-cmd\/[A-Za-z0-9_.-]+$/);
  assert.match(t.commit,/^[a-f0-9]{40}$/);
 }
});
test('audit reports, not target source files, are persisted with SHA-pinned uploader',()=>{
 const y=readFileSync(new URL('../.github/workflows/cyber-hak-ci.yml',import.meta.url),'utf8');
 assert.match(y,/uses: actions\/upload-artifact@[a-f0-9]{40}/);
 assert.match(y,/path: audit-output\/ci\//);
 assert.match(y,/retention-days: 30/);
 assert.doesNotMatch(y,/path: \*\*/);
});
