import {scanGitCheckout} from '../src/private-checkout-audit.mjs';
const args=process.argv.slice(2);
if(args.length!==8)throw Error('AUDIT_ARGUMENT_COUNT_DENIED');
const opts={};
for(let i=0;i<args.length;i+=2){
 if(!['--root','--out','--commit','--scanner'].includes(args[i])||opts[args[i]])throw Error('AUDIT_OPTION_DENIED');
 opts[args[i]]=args[i+1];
}
if(!opts['--root']||!opts['--out']||!opts['--commit']||!opts['--scanner'])throw Error('AUDIT_INPUT_DENIED');
try{
 const report=await scanGitCheckout({root:opts['--root'],output:opts['--out'],expectedSha:opts['--commit'],scannerSha:opts['--scanner']});
 console.log(JSON.stringify({status:'CYBER_HAK_PRIVATE_SOURCE_STATIC_AUDIT',source:report.sourceSha,scanner:report.scannerSha,
  files:report.coverage.length,high:report.counts.HIGH,medium:report.counts.MEDIUM,
  verdict:report.verdict,ownerApproval:'NOT_VERIFIED',independentHumanQA:false,production:'DENIED'}));
 if(report.counts.HIGH>0)process.exitCode=1;
}catch(e){console.error('CYBER_HAK_AUDIT_BLOCKED',String(e.message).replace(/[^A-Z0-9_]/g,''));process.exitCode=2}
