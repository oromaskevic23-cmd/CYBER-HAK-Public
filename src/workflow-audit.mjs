import {parseDocument, LineCounter, visit, isAlias} from 'yaml';
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const immutable = ref => /@[a-fA-F0-9]{40}$/.test(ref) || /^docker:\/\/[^\s]+@sha256:[a-fA-F0-9]{64}$/.test(ref);
const local = ref => /^(?:\.\/|\$\/)/.test(ref) && !ref.includes('@') && !ref.split('/').includes('..');
const normalize = expression => expression.replace(/\[\s*['"]([^'"]+)['"]\s*\]/g,'.$1').replace(/\s+/g,'');
const untrusted = expression => /\b(?:inputs\.|github\.head_ref\b|github\.event\.(?:inputs\.|pull_request\.(?:title|body|head\.(?:ref|label|repo\.(?:name|full_name)))\b|issue\.(?:title|body)\b|(?:comment|review|review_comment)\.body\b|discussion\.(?:title|body)\b|head_commit\.(?:message|author\.(?:name|email))\b|commits\[))/.test(normalize(expression));
const interpolated = script => [...script.matchAll(/\$\{\{[\s\S]*?\}\}/g)].some(m => untrusted(m[0]));
export const downloadsAndExecutes = script => /(?:^|[;\n&])\s*(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b/i.test(script.replace(/\\\r?\n/g,' '));

function document(content) {
  const counter = new LineCounter();
  const doc = parseDocument(content,{version:'1.2',schema:'core',uniqueKeys:true,stringKeys:true,
    strict:true,prettyErrors:false,logLevel:'silent',lineCounter:counter});
  if(doc.errors.length || doc.warnings.length || doc.directives.yaml.version !== '1.2') throw new Error('UNSUPPORTED_YAML');
  visit(doc, (_key,node) => { if(isAlias(node) || node?.anchor) throw new Error('UNSUPPORTED_YAML'); });
  const data = doc.toJS({maxAliasCount:0});
  if(!object(data)) throw new Error('UNSUPPORTED_YAML');
  return {data, line:path => counter.linePos(doc.getIn(path,true)?.range?.[0] ?? 0).line};
}

export function scanWorkflow(content) {
  const findings=[];
  const add=(rule_id,line,confidence='HIGH')=>findings.push({rule_id,line,confidence});
  let parsed;
  try { parsed=document(content); }
  catch { return {findings:[{rule_id:'WORKFLOW_PARSE',line:1,confidence:'HIGH'}],complete:false}; }
  const {data:w,line}=parsed;
  const triggers=typeof w.on==='string' ? [w.on] : Array.isArray(w.on) ? w.on : object(w.on) ? Object.keys(w.on) : [];
  if(!triggers.length || !object(w.jobs) || !Object.keys(w.jobs).length) {
    return {findings:[{rule_id:'WORKFLOW_PARSE',line:1,confidence:'HIGH'}],complete:false};
  }
  let complete=true;
  const malformed=p=>{complete=false;add('WORKFLOW_PARSE',line(p));};
  const checkEnv=(env,p)=>{
    if(!object(env)) return;
    if(env.NODE_TLS_REJECT_UNAUTHORIZED===0 || env.NODE_TLS_REJECT_UNAUTHORIZED==='0') add('TLS_DISABLED',line([...p,'NODE_TLS_REJECT_UNAUTHORIZED']));
    if(env.GIT_SSL_NO_VERIFY===true || env.GIT_SSL_NO_VERIFY==='true') add('TLS_DISABLED',line([...p,'GIT_SSL_NO_VERIFY']));
  };
  checkEnv(w.env,['env']);
  const checkUse=(ref,p)=>{
    if(typeof ref!=='string') { malformed(p); return; }
    if(!immutable(ref) && !local(ref)) add('ACTION_UNPINNED',line(p));
  };
  for(const [jobId,job] of Object.entries(w.jobs)) {
    const jp=['jobs',jobId];
    if(!object(job)) { malformed(jp); continue; }
    checkEnv(job.env,[...jp,'env']);
    const pp=Object.hasOwn(job,'permissions') ? [...jp,'permissions'] : ['permissions'];
    const permissions=Object.hasOwn(job,'permissions') ? job.permissions : w.permissions;
    if(permissions===undefined) add('TOKEN_PERMISSIONS_IMPLICIT',line(jp),'MEDIUM');
    else if(permissions==='write-all') add('TOKEN_WRITE_ALL',line(pp));
    else if(object(permissions)) {
      if(Object.values(permissions).some(v=>v==='write')) add('TOKEN_WRITE_SCOPE',line(pp),'MEDIUM');
      if(Object.values(permissions).some(v=>!['none','read','write'].includes(v))) malformed(pp);
    } else if(permissions!=='read-all') malformed(pp);
    if(Object.hasOwn(job,'uses')) { checkUse(job.uses,[...jp,'uses']); continue; }
    if(!Array.isArray(job.steps)) { malformed(jp); continue; }
    const runs=Array.isArray(job['runs-on']) ? job['runs-on'] : [job['runs-on']];
    if(triggers.some(t=>['pull_request','pull_request_target'].includes(t)) && runs.includes('self-hosted'))
      add('UNTRUSTED_SELF_HOSTED',line([...jp,'runs-on']),'MEDIUM');
    for(const [i,step] of job.steps.entries()) {
      const sp=[...jp,'steps',i];
      if(!object(step)) { malformed(sp); continue; }
      checkEnv(step.env,[...sp,'env']);
      if(step.uses!==undefined) {
        checkUse(step.uses,[...sp,'uses']);
        if(typeof step.uses==='string' && /^actions\/checkout@/i.test(step.uses)) {
          if(step.with?.['persist-credentials'] !== false && step.with?.['persist-credentials'] !== 'false')
            add('CHECKOUT_CREDENTIALS',line([...sp,'uses']));
          if(triggers.includes('pull_request_target') && typeof step.with?.ref==='string' && /github\.event\.pull_request\.head\b/.test(normalize(step.with.ref)))
            add('PR_TARGET_UNTRUSTED_CHECKOUT',line([...sp,'with','ref']));
        }
      }
      const scripts=[['run',step.run]];
      if(typeof step.uses==='string' && /^actions\/github-script@/i.test(step.uses)) scripts.push(['script',step.with?.script]);
      for(const [field,script] of scripts) {
        if(script===undefined) continue;
        const p=field==='run' ? [...sp,'run'] : [...sp,'with','script'];
        if(typeof script!=='string') { malformed(p); continue; }
        if(interpolated(script)) add('SCRIPT_INTERPOLATION',line(p));
        if(downloadsAndExecutes(script)) add('DOWNLOAD_EXECUTE',line(p));
      }
    }
  }
  return {findings,complete};
}

export function scanContainerConfig(content) {
  const findings=[];
  try {
    const {data,line}=document(content);
    const walk=(v,p=[])=>{
      if(Array.isArray(v)) return v.forEach((x,i)=>walk(x,[...p,i]));
      if(!object(v)) return;
      for(const [key,value] of Object.entries(v)) {
        const path=[...p,key];
        if(['privileged','allowPrivilegeEscalation'].includes(key) && value===true)
          findings.push({rule_id:'PRIVILEGED_CONTAINER',line:line(path),confidence:'HIGH'});
        if(object(value) || Array.isArray(value)) walk(value,path);
      }
    };
    walk(data);
    return {findings,complete:true};
  } catch { return {findings:[],complete:false}; }
}
