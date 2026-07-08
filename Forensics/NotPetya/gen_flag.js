"use strict";
const fs = require("fs"), path = require("path"), crypto = require("crypto");

const PREFIX = "LYKNCTF{";
const uuid = crypto.randomUUID();
const flag = PREFIX + uuid + "}";

const p1 = PREFIX + uuid.slice(0, 9);
const p2 = uuid.slice(9, 18);
const p3 = uuid.slice(18, 27);
const p4 = uuid.slice(27, 36) + "}";
if (p1 + p2 + p3 + p4 !== flag) throw new Error("split mismatch");

const p1enc = Buffer.from(p1, "utf8").toString("base64");
const p2m   = "f2{" + p2 + "}";
const p3m   = "f3{" + p3 + "}";

fs.writeFileSync("flag.txt", flag + "\n");

fs.writeFileSync("pieces.json", JSON.stringify(
  { flag, uuid, p1, p2, p3, p4, p1enc, p2m, p3m,
    note: "p1enc=base64(p1) into GPT name | p2m=f2{p2} XOR serial @backupVBR+0x80 | p3m=f3{p3} slack record AES | p4=part4.txt in flag.zip" },
  null, 2) + "\n");

const DIR = "flag";
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

fs.writeFileSync(path.join(DIR, "part4.txt"), p4);

const inZip = fs.readdirSync(DIR).filter(n => fs.statSync(path.join(DIR, n)).isFile());
const hasBig = inZip.some(n => n !== "part4.txt" && fs.statSync(path.join(DIR, n)).size > 100_000);

console.log("flag.txt  =", flag);
console.log("pieces    :");
console.log("  p1 (GPT name b64) =", JSON.stringify(p1), "-> b64", JSON.stringify(p1enc));
console.log("  p2 (XOR serial  ) =", JSON.stringify(p2), "-> on-disk", JSON.stringify(p2m));
console.log("  p3 (AES record  ) =", JSON.stringify(p3), "-> on-disk", JSON.stringify(p3m));
console.log("  p4 (zip part4   ) =", JSON.stringify(p4), "len", p4.length);
console.log("flag/     : will go into zip ->", inZip.join(", "));
if (!hasBig) console.log("  [!] warning: no large/high entropy file found -> ZipCrypto might be vulnerable to bkcrack. Add an .ogg/.mp4 file.");
console.log("part4.txt : written");
console.log("=> next: node make_zip.js <serial>   (zip flag/ folder)");
