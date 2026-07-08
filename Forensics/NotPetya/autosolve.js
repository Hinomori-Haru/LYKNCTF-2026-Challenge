// Auto-solver infected.vhd
// node autosolve.js [infected.vhd]
const crypto = require('crypto'), fs = require('fs');

// ---- .NET new Random(seed) legacy subtractive ----
const MBIG = 2147483647, MSEED = 161803398;
class NetRandom {
  constructor(seed){
    this.s = new Array(56).fill(0);
    let sub = (seed === -2147483648) ? MBIG : Math.abs(seed);
    let mj = MSEED - sub; this.s[55] = mj; let mk = 1;
    for (let i=1;i<55;i++){ let ii=(21*i)%55; this.s[ii]=mk; mk=mj-mk; if(mk<0)mk+=MBIG; mj=this.s[ii]; }
    for (let k=0;k<4;k++) for(let i=1;i<56;i++){ this.s[i]-=this.s[1+(i+30)%55]; if(this.s[i]<0)this.s[i]+=MBIG; }
    this.inext=0; this.inextp=21;
  }
  samp(){
    this.inext=(this.inext+1>=56)?1:this.inext+1;
    this.inextp=(this.inextp+1>=56)?1:this.inextp+1;
    let r=this.s[this.inext]-this.s[this.inextp];
    if(r===MBIG)r--; if(r<0)r+=MBIG; this.s[this.inext]=r; return r;
  }
  nextBytes(n){ return Buffer.from(Array.from({length:n}, ()=>this.samp()%256)); }
}

const SEED = 956377;
const SALT = Buffer.from("yuneko_dev_", "ascii");
const hx = n => "0x"+n.toString(16).toUpperCase();
const indexOf = (hay,needle,from=0) => hay.indexOf(needle,from);

const IMG = process.argv[2] || "infected.vhd";
const d = fs.readFileSync(IMG);
console.log("file size =", d.length, "("+hx(d.length)+")");

// ===== Phase 0: footer + backup GPT (Fixed VHD) =====
const footerOff = d.length - 512;
const bGptOff   = d.length - 1024;
console.log("VHD footer @", hx(footerOff), "magic:", JSON.stringify(d.toString("latin1",footerOff,footerOff+8)));
console.log("backup GPT @", hx(bGptOff),  "magic:", JSON.stringify(d.toString("latin1",bGptOff,bGptOff+8)));
console.log("LBA1 (prim GPT hdr) @0x200 all-zero:",
  d.subarray(0x200,0x400).every(b=>b===0));

// ===== Phase 1: GPT entry[0] @ LBA2 (0x400) =====
const pe = 0x400;
const firstLBA = Number(d.readBigUInt64LE(pe+0x20));
const lastLBA  = Number(d.readBigUInt64LE(pe+0x28));
const nameRaw  = d.subarray(pe+0x38, pe+0x38+72);
const nameStr = nameRaw.toString("utf16le").replace(/[\0 ]+$/,"");    // GPT name = base64(p1)
const m1 = Buffer.from(nameStr, "base64").toString("latin1");          // frag 1
console.log("[P1] name(base64) =", JSON.stringify(nameStr));
console.log("\n[P1] firstLBA="+firstLBA, "lastLBA="+lastLBA, "name@"+hx(pe+0x38));
console.log("[P1] Frag 1 =", JSON.stringify(m1));

// ===== Phase 2: VBR =====
const partStart = firstLBA*512;
const backupVBR = partStart + (lastLBA-firstLBA)*512;          // (size-1)*512
const vbr = d.subarray(partStart, partStart+512);
const bvbr = d.subarray(backupVBR, backupVBR+512);
const bps2 = bvbr.readUInt16LE(0x0B), spc2 = bvbr[0x0D];
const mftLCN2 = Number(bvbr.readBigUInt64LE(0x30));
const volSer2 = bvbr.subarray(0x48,0x50);
console.log("\n[P2] partStart="+hx(partStart), "backupVBR="+hx(backupVBR));
console.log("[P2] main VBR @"+hx(partStart)+" =", JSON.stringify(vbr.toString("latin1",0,40)));
console.log("[P2] backupVBR bps="+bps2, "spc="+spc2, "mftLCN="+hx(mftLCN2), "volSerial="+volSer2.toString("hex").toUpperCase());
const xorSer = (buf,ser) => Buffer.from(Array.from(buf,(b,i)=>b^ser[i%ser.length]));
console.log("[P2] backupVBR+0x80 @"+hx(backupVBR+0x80)+" (XOR serial) =", d.subarray(backupVBR+0x80, backupVBR+0x80+32).toString("hex"));
const win2 = xorSer(d.subarray(backupVBR+0x80, backupVBR+0x80+32), volSer2).toString("latin1");
const mm2 = win2.match(/f2\{([^}]*)\}/);
const m2 = mm2 ? mm2[1] : "MISSING";
console.log("[P2] Frag 2 @"+hx(backupVBR+0x80)+" (XOR serial, marker f2{}) =", JSON.stringify(m2));

// ===== Phase 3: AES =====
const mftByte = partStart + mftLCN2*spc2*bps2;
const REC = 1024;
const rb  = new NetRandom(SEED).nextBytes(32);
const key = crypto.createHash("sha256").update(Buffer.concat([rb,SALT,volSer2])).digest();
console.log("\n[P3] mftByte="+hx(mftByte));
console.log("[P3] KEY =", key.toString("hex").toUpperCase());

const FILE = Buffer.from("FILE","latin1");
const flagU16 = Buffer.from("flag.zip","utf16le");
const decRec = (buf) => {
  const c = crypto.createDecipheriv("aes-256-cbc", key, Buffer.alloc(16));
  c.setAutoPadding(false);
  return Buffer.concat([c.update(buf), c.final()]);
};

const applyFixup = (r) => {
  const usaOff = r.readUInt16LE(0x04), usaCnt = r.readUInt16LE(0x06);
  if (usaOff < 0x2A || usaOff + usaCnt*2 > REC) return r;
  for (let i=1;i<usaCnt;i++){
    const sectorEnd = i*512 - 2;
    if (sectorEnd+2 > r.length) break;
    r.writeUInt16LE(r.readUInt16LE(usaOff + i*2), sectorEnd);
  }
  return r;
};

const recHasData = (r) => {
  let a = r.readUInt16LE(0x14);
  while (a+8 <= REC){
    const t = r.readUInt32LE(a); if (t===0xFFFFFFFF) break;
    const len = r.readUInt32LE(a+4); if (len<=0 || a+len>REC) break;
    if (t===0x80) return true;
    a += len;
  }
  return false;
};

let recAbs = -1, rec = null, recFx = null;
const SCAN = 8*1024*1024;
for (let off=mftByte; off+REC<=Math.min(mftByte+SCAN, d.length-512); off+=REC){
  const blk = d.subarray(off, off+REC);
  if (blk.subarray(0,4).equals(FILE)) continue;
  if (blk.every(b=>b===0)) continue;
  let cand;
  try { cand = decRec(blk); } catch { continue; }
  if (!cand.subarray(0,4).equals(FILE)) continue;
  const cfx = applyFixup(Buffer.from(cand));
  if (indexOf(cfx, flagU16) >= 0 && recHasData(cfx)){
    recAbs = off; rec = cand; recFx = cfx; break;
  }
}
if (recAbs < 0) throw new Error("recAbs < 0 ???");
console.log("[P3] recAbs="+hx(recAbs));

const mk3  = recFx.indexOf(Buffer.from([0xFF,0xFF,0xFF,0xFF]), 0x30);
const win3 = mk3 >= 0 ? recFx.toString("latin1", mk3+8, mk3+8+32) : "";
const mm3  = win3.match(/f3\{([^}]*)\}/);
const m3 = mm3 ? mm3[1] : "MISSING";
console.log("[P3] Frag 3 (marker f3{}) =", JSON.stringify(m3));

// ===== Phase 4: zip =====
const zlib = require('zlib');
const clusterSize = spc2 * bps2;
const ZIP_PASSWORD = key.toString("hex").toUpperCase();

// ---- ZipCrypto (PKWARE traditional) decrypt ----
const CRCTAB = (()=>{ const t=new Uint32Array(256);
  for(let n=0;n<256;n++){ let c=n; for(let k=0;k<8;k++) c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1); t[n]=c>>>0; } return t; })();
const crcUpd = (crc,b)=> (CRCTAB[(crc^b)&0xff] ^ (crc>>>8)) >>> 0;
function zipCryptoDecrypt(buf, pw){
  let k0=0x12345678,k1=0x23456789,k2=0x34567890;
  const upd=(b)=>{ k0=crcUpd(k0,b); k1=((k1+(k0&0xff))>>>0); k1=(Math.imul(k1,134775813)+1)>>>0; k2=crcUpd(k2,(k1>>>24)&0xff); };
  const dec=(b)=>{ const t=(k2|2)>>>0; const p=b^((Math.imul(t,(t^1))>>>8)&0xff); upd(p); return p; };
  for(const c of Buffer.from(pw,"latin1")) upd(c);
  const out=Buffer.alloc(buf.length);
  for(let i=0;i<buf.length;i++) out[i]=dec(buf[i]);
  return out.subarray(12);
}

function dataRuns(r){
  let a = r.readUInt16LE(0x14);
  while (a+4 <= REC){
    const type = r.readUInt32LE(a); if (type===0xFFFFFFFF) break;
    const len = r.readUInt32LE(a+4); if (len<=0 || a+len>REC) break;
    if (type===0x80 && r[a+9]===0 && r[a+8]===1){
      const runOff=r.readUInt16LE(a+0x20), realSize=Number(r.readBigUInt64LE(a+0x30));
      let p=a+runOff, lcn=0, runs=[];
      while (r[p]!==0){
        const h=r[p++], lenSz=h&0xf, offSz=h>>4;
        let cnt=0; for(let i=0;i<lenSz;i++) cnt+=r[p++]*(2**(8*i));
        let off=0; for(let i=0;i<offSz;i++) off+=r[p++]*(2**(8*i));
        if (offSz>0 && (r[p-1]&0x80)) off -= 2**(8*offSz);
        lcn += off; runs.push([lcn, cnt]);
      }
      return { runs, realSize };
    }
    a += len;
  }
  return null;
}

const dr = dataRuns(recFx);
let m4="MISSING", fragInfo="$DATA not found";
if (dr){
  const runBytes = dr.runs.reduce((s,[,c])=>s+c*clusterSize, 0);
  fragInfo = dr.runs.length+" fragment(s), realSize="+dr.realSize+" byte, runlist="+runBytes+" byte";
  if (runBytes < dr.realSize)
    fragInfo += "  [!] RUNLIST < realSize -> missing "+(dr.realSize-runBytes)+" byte (fixup/parse err?)";
  const parts = dr.runs.map(([lcn,cnt]) => {
    const start = partStart + lcn*clusterSize;
    return d.subarray(start, start + cnt*clusterSize);
  });
  const zipBuf = Buffer.concat(parts).subarray(0, dr.realSize);
  fs.writeFileSync("flag_recovered.zip", zipBuf);
  try {                                                   // unzip part4.txt
    let eo=-1; for(let i=zipBuf.length-22;i>=0;i--){ if(zipBuf.readUInt32LE(i)===0x06054b50){eo=i;break;} }
    if (eo<0) throw new Error("EOCD not found");
    const cnt=zipBuf.readUInt16LE(eo+10); let pp=zipBuf.readUInt32LE(eo+16);
    for(let n=0;n<cnt;n++){
      const method=zipBuf.readUInt16LE(pp+10), cs=zipBuf.readUInt32LE(pp+20);
      const nl=zipBuf.readUInt16LE(pp+28), el=zipBuf.readUInt16LE(pp+30), cl=zipBuf.readUInt16LE(pp+32);
      const lho=zipBuf.readUInt32LE(pp+42), name=zipBuf.toString("latin1",pp+46,pp+46+nl);
      if(name==="part4.txt"){
        const gp=zipBuf.readUInt16LE(pp+8);                       // GP flag (bit0 = ZipCrypto)
        const lnl=zipBuf.readUInt16LE(lho+26), lel=zipBuf.readUInt16LE(lho+28), st=lho+30+lnl+lel;
        let comp=zipBuf.subarray(st, st+cs);
        if(gp & 1) comp=zipCryptoDecrypt(comp, ZIP_PASSWORD);
        m4=(method===8?zlib.inflateRawSync(comp):comp).toString("latin1"); break;
      }
      pp+=46+nl+el+cl;
    }
  } catch(e){ m4="UNZIP_FAIL: "+e.message; }
}
console.log("\n[P4] data-runs:", fragInfo, "-> flag_recovered.zip");
console.log("[P4] zip password (= key Phase 3) =", ZIP_PASSWORD);
console.log("[P4] Frag 4 (part4.txt) =", JSON.stringify(m4));

// ===== Recover VHD =====
const out = Buffer.from(d);

// -- GPT header --
const diskLastLBA = BigInt(d.length - 512) / 512n - 1n;
const hdr = Buffer.from(d.subarray(bGptOff, bGptOff+512));
hdr.writeBigUInt64LE(1n, 0x18);
hdr.writeBigUInt64LE(diskLastLBA, 0x20);
hdr.writeBigUInt64LE(2n, 0x48);
const numE = hdr.readUInt32LE(0x50), szE = hdr.readUInt32LE(0x54);
const arr  = d.subarray(0x400, 0x400 + numE*szE);
hdr.writeUInt32LE(zlib.crc32(arr) >>> 0, 0x58);
const hsz = hdr.readUInt32LE(0x0C);
hdr.writeUInt32LE(0, 0x10);
const hcrc = zlib.crc32(hdr.subarray(0, hsz)) >>> 0;
hdr.writeUInt32LE(hcrc, 0x10);
hdr.copy(out, 0x200);
out.fill(0, 0x200+512, 0x400);

bvbr.copy(out, partStart);

rec.copy(out, recAbs);

fs.writeFileSync("recovered.vhd", out);
console.log("\n[restore] GPT hdr CRC32=0x"+hcrc.toString(16).toUpperCase(),
            "| VBR <- backupVBR | record <- decrypted");
console.log("[restore] -> recovered.vhd ("+out.length+" byte)");

// ===== Flag =====
const FLAG = m1+m2+m3+m4;
console.log("\n==================================================");
console.log("FLAG =", FLAG);
console.log("==================================================");

// ===== VERIFY =====
let bad = [];
if (m4 === "MISSING" || m4.startsWith("UNZIP_FAIL")) bad.push("Flag 4 ("+m4+")");
if (/MISSING/.test(m1+m2+m3))                          bad.push("Flag 1/2/3 missing");
try {
  const fp = require('path').join(__dirname, "flag.txt");
  if (fs.existsSync(fp)) {
    const want = fs.readFileSync(fp, "utf8").trim();
    if (FLAG === want) console.log("[VERIFY] PASS");
    else { console.log("[VERIFY] FAIL — flag.txt:", JSON.stringify(want)); bad.push("!= flag.txt"); }
  } else {
    console.log("[VERIFY] (skip)");
  }
} catch(e){ console.log("[Error]:", e.message); }
if (bad.length) {
  console.error("\n[FAIL]:" + bad.join(", "));
  process.exit(1);
}
