// Checks this package's own reviewed source. It is not used on audited repositories.
import {readdirSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
for(const dir of ['src','test','tools']) {
  for(const name of readdirSync(new URL('../'+dir+'/',import.meta.url)).sort()) {
    if(name.endsWith('.mjs')) execFileSync(process.execPath,['--check',new URL('../'+dir+'/'+name,import.meta.url).pathname],{stdio:'inherit'});
  }
}
