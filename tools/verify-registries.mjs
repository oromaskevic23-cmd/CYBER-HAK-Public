// Read-only public registry conformance verification, Node.js standard library only.
import {readFileSync} from "node:fs";
import {validatePublicRegistries} from "../src/registry-validation.mjs";
const read=(path)=>JSON.parse(readFileSync(new URL("../"+path,import.meta.url),"utf8"));
const result=validatePublicRegistries({
 manifest:read("PUBLIC-MANIFEST.json"),
 capabilities:read("registry/CAPABILITY-FAMILIES.json"),
 threats:read("registry/THREAT-CATEGORIES.json"),
 severity:read("registry/INCIDENT-SEVERITY.json")
});
process.stdout.write(JSON.stringify(result,null,2)+"\n");
