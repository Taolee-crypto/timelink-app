'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const directory=path.resolve(__dirname,'../tests');
const files=fs.readdirSync(directory).filter(name=>name.endsWith('.test.js')).sort().map(name=>path.join(directory,name));
if(files.length===0){console.error('No test files found');process.exit(1);}
const result=spawnSync(process.execPath,['--test',...files],{stdio:'inherit',env:process.env});
if(result.error){console.error(result.error);process.exit(1);}
process.exit(result.status===null?1:result.status);
