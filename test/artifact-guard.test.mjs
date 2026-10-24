import test from "node:test";
import assert from "node:assert/strict";
import {inspectArtifact} from "../src/artifact-guard.mjs";

test("normal public documentation is review-only, never approved",()=>{
  const r=inspectArtifact({path:"docs/readme.md",content:"# Intro\n\nSafe instructions\n"});
  assert.equal(r.decision,"REVIEW_ONLY");
  assert.equal(r.release,"DENIED");
  assert.equal(r.execution,"NOT_RUN");
  assert.equal(r.reasons.length,0);
  assert.match(r.content_sha256,/^[0-9a-f]{64}$/);
});
test("private or secret classification always denied",()=>{
  for(const classification of ["PRIVATE","SECRET","RESTRICTED","public",null]){
    const r=inspectArtifact({path:"docs/x.md",content:"safe",classification});
    assert.equal(r.decision,"DENY");
    assert.ok(r.reasons.includes("NON_PUBLIC_CLASSIFICATION"));
  }
});
test("empty, absolute and platform-specific paths fail closed",()=>{
 for(const path of ["","/etc/passwd","C:\\keys\\my.key","dir\\file.js","dir//file.js","../a.md","a/../b.md","a/./b.md","a/%2e%2e/b.js","a//b.md"]){
   assert.equal(inspectArtifact({path,content:"ok"}).decision,"DENY",path);
 }
});
test("hidden, secret and key-file paths fail closed",()=>{
 for(const path of [".env","foo/.env.production","secrets.json","nested/private.pem","keys/id_ed25519","repo/.git/config","authorized_keys",".github/workflows/a.yml","keys/config.p12"]){
   assert.equal(inspectArtifact({path,content:"safe"}).decision,"DENY",path);
 }
});
test("unicode obfuscation cannot bypass path check",()=>{
 const p="do\u202ecs/readme.md";
 const r=inspectArtifact({path:p,content:"hello"});
 assert.equal(r.decision,"DENY");
 assert.ok(r.reasons.includes("INVALID_ARTIFACT_PATH"));
});
test("Unicode hidden controls in content are rejected",()=>{
 for(const c of ["good\u200btext","line\u202eorder","text\u0000byte"]){
  const r=inspectArtifact({path:"docs/x.md",content:c});
  assert.equal(r.decision,"DENY");
  assert.ok(r.reasons.includes("HIDDEN_OR_CONTROL_CHARACTERS"));
 }
});
test("normal newlines and tabs are legitimate source text",()=>{
 const r=inspectArtifact({path:"src/engine.js",content:"const task = 1;\n\t// done\r\n"});
 assert.equal(r.decision,"REVIEW_ONLY");
});
test("recognizes private-key headers without echoing contents",()=>{
 const content="-----BEGIN PRIVATE KEY-----\nDO-NOT-LEAK";
 const result=inspectArtifact({path:"docs/test.txt",content});
 assert.equal(result.decision,"DENY");
 assert.ok(result.reasons.includes("PRIVATE_KEY_MATERIAL"));
 assert.equal(JSON.stringify(result).includes("DO-NOT-LEAK"),false);
});
test("detects Groq and other token-like strings",()=>{
 for(const [prefix,code] of [["gsk_","GROQ_API_KEY"],["sk-proj-","OPENAI_API_KEY"],["ghp_","GITHUB_TOKEN"]]){
  const text=prefix+"A".repeat(30);
  const result=inspectArtifact({path:"docs/example.md",content:text});
  assert.equal(result.decision,"DENY");
  assert.ok(result.reasons.includes(code));
  assert.equal(JSON.stringify(result).includes(text),false);
 }
});
test("does not assume a short placeholder is a real key",()=>{
 const r=inspectArtifact({path:"docs/example.md",content:"GROQ_API_KEY=gsk_example"});
 assert.equal(r.decision,"REVIEW_ONLY");
});
test("restricts maximum byte size",()=>{
 const r=inspectArtifact({path:"docs/example.md",content:"ы".repeat(140000)});
 assert.equal(r.decision,"DENY");
 assert.ok(r.reasons.includes("CONTENT_SIZE_LIMIT"));
});
test("rejects non-text content and missing paths",()=>{
 assert.equal(inspectArtifact({path:"x.md",content:Buffer.from("abc")}).decision,"DENY");
 assert.equal(inspectArtifact({content:"hello"}).decision,"DENY");
});
test("even clear artifacts cannot bypass publication review",()=>{
 const r=inspectArtifact({path:"registry/manifest.json",content:"{}"});
 assert.equal(r.authority,"NONE");
 assert.equal(r.release,"DENIED");
});
