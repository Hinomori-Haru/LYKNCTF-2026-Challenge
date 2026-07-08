# NotPet(y)a — Forensics Writeup

**Challenge:** NotPet(y)a  
**Category:** Forensics  
**Author:** @yuneko.dev (Ellie)  
**Points:** 500

> This writeup was prepared with the help of AI.

## Challenge Description

Ellie split the flag into four fragments and hid them throughout a VHD image. To make things even more interesting, she deliberately corrupted the image using `encryptor.exe`.

Follow the echoes, recover the four fragments in sequence, and reconstruct the final flag.

**Flag format:** `LYKNCTF{<uuid>}` (`<uuid>` is a randomly generated UUID string.)

**Note:** Resist the temptation to skip ahead -- the later fragments may depend on clues uncovered earlier.

---

## Initial Thoughts

- Ellie's original intention was for this challenge to be solved linearly, by progressively restoring the VHD file into a readable format.
- But somehow everyone always managed to solve frag 1 and frag 4 first 😭

### Triage

- Since the challenge description explicitly states the file is corrupted, it definitely won't mount. Attempting to mount will immediately throw an error.

### File Size

```
File size = 104,858,112 bytes = 0x6400200
         = 0x6400000 (100 MB) + 0x200 (512 bytes)
```

The extra 512 bytes at the **end of the file** — what are they? This is a **Fixed VHD** — a Microsoft disk image format. Fixed VHD = raw disk image + **512-byte footer** at the end (magic `conectix`):

```
[ raw disk data (100 MB = 0x6400000 bytes) ][ VHD footer 512B "conectix" ]
^                                          ^                             ^
0x0                                   0x6400000                     0x6400200 (EOF)
```

> **Theory — Fixed VHD:**
> VHD (Virtual Hard Disk) is a Microsoft Hyper-V format. "Fixed" means the entire disk capacity is pre-allocated. The 512-byte footer at the end contains metadata (disk type, size, CHS geometry...) and starts with the magic string `conectix`. This footer is **NOT** part of the disk data — it is VHD container metadata.

Calculations:

- **Actual disk** = `0x6400000` bytes = `204,800` sectors × 512 bytes/sector → LBA 0..204799
- **VHD footer** = offset `0x6400000` → magic `conectix` → **ignore** when analyzing the disk
- **Backup GPT Header** = last LBA of the _disk_ = LBA 204799 = `0x6400000 - 0x200` = **`0x63FFE00`**

| Offset      | Content                                  |
| ----------- | ---------------------------------------- |
| `0x63FFE00` | **Backup GPT Header** (magic `EFI PART`) |
| `0x6400000` | VHD footer (magic `conectix`) — NOT GPT! |
| `0x6400200` | End of file                              |

---

## Phase 1 — Recover GPT → Fragment 1

### Theory — What is GPT?

**GPT** (GUID Partition Table) is the modern partition scheme, replacing MBR. Structure:

```
LBA 0:  Protective MBR (512 bytes) — for backward compatibility
LBA 1:  GPT Primary Header (512 bytes) — magic "EFI PART", contains partition entry array location
LBA 2+: Partition Entry Array — each entry 128 bytes, describes one partition
  ...
LBA N-1: Backup GPT Header — redundant copy of LBA 1
```

The encryptor **zeroed out the entire LBA 1** (GPT Primary Header), but **did NOT touch**:

- **Partition Entry Array** at LBA 2 (`0x400`) → still intact
- **Backup GPT Header** at the last LBA → still intact

### Reading the Partition Entry

Since the encryptor only wiped LBA1 without touching LBA2, the **partition entry array remains intact** at offset `0x400`.

Each GPT Partition Entry has a 128-byte structure:

| Offset (within entry) | Size   | Meaning                                       |
| --------------------- | ------ | --------------------------------------------- |
| `+0x00`               | 16     | Partition Type GUID                           |
| `+0x10`               | 16     | Unique Partition GUID                         |
| **`+0x20`**           | **8**  | **First LBA** (first sector of the partition) |
| **`+0x28`**           | **8**  | **Last LBA** (last sector of the partition)   |
| `+0x30`               | 8      | Attribute flags                               |
| **`+0x38`**           | **72** | **Partition Name** (UTF-16LE, null-padded)    |

Entry[0] starts at file offset `0x400`. The Name field starts at `0x400 + 0x38 = 0x438`.

```js
const d = require('fs').readFileSync('infected.vhd');

// Read partition entry at 0x400
const pe = 0x400;
const firstLBA = Number(d.readBigUInt64LE(pe + 0x20)); // = 128
const lastLBA = Number(d.readBigUInt64LE(pe + 0x28)); // = 204671

// Read partition name (72 bytes UTF-16LE)
const nameRaw = d.subarray(pe + 0x38, pe + 0x38 + 72);
const nameStr = nameRaw.toString('utf16le').replace(/[\0 ]+$/, '');
// → "TFlLTkNURns3Zjg3ZjExNy0="
```

### Decoding the Partition Name

The string `TFlLTkNURns3Zjg3ZjExNy0=` looks like... **Base64**! (Charset `A-Za-z0-9+/`, ends with `=`.)

> **Why Base64?** If the plaintext `LYKNCTF{...}` were stored directly in the partition name, a simple `strings infected.vhd | grep LYKNCTF` would find it immediately — too easy. Base64 encoding adds one extra step that prevents `grep` from catching it.

```js
const m1 = Buffer.from('TFlLTkNURns3Zjg3ZjExNy0=', 'base64').toString('latin1');
// → "LYKNCTF{7f87f117-"
```

**🏴 Fragment 1:** `LYKNCTF{7f87f117-`

---

## Phase 2 — Recover NTFS VBR → Fragment 2

### Primary VBR Overwritten

From Phase 1, we know the partition starts at:

```
partStart = firstLBA × 512 = 128 × 512 = 0x10000
```

Reading at offset `0x10000` (first sector of the partition — should be the NTFS VBR):

```
"Ooops, your volume has been trashed by the NotPeta Echo..."
```

This is the **ransom note** that the encryptor overwrote onto the original VBR. No VBR → can't read the BPB (BIOS Parameter Block) → can't locate the MFT.

> Note:

- This was actually a mistake by Ellie when coding the autosolve.js script — she didn't verify whether the content of note.txt actually existed in the infected.vhd file.
- Because the hint portion at the end of the note was lost, it accidentally became the hardest part of the entire challenge 😅
- After Ellie re-posted the missing frag 2 hint on the CTF platform, many more teams solved it — congrats!

### Theory — NTFS Backup VBR

> **NTFS (New Technology File System)** always keeps a backup copy of the VBR (Volume Boot Record) at the **LAST sector of the partition**.

```
backupVBR = partStart + (lastLBA - firstLBA) × 512
         = 0x10000 + (204671 - 128) × 512
         = 0x63EFE00
```

Verification: reading at `0x63EFE00`, we find the magic `NTFS    ` (4 bytes `NTFS` + 4 bytes space) at offset +3 → confirmed VBR!

### Reading BPB from the Backup VBR

From the backup VBR, extract the critical NTFS parameters:

| Offset (within VBR) | Size  | Meaning                                      | Value              |
| ------------------- | ----- | -------------------------------------------- | ------------------ |
| `+0x0B`             | 2     | **Bytes Per Sector** (bps)                   | `512`              |
| `+0x0D`             | 1     | **Sectors Per Cluster** (spc)                | `8`                |
| `+0x30`             | 8     | **MFT LCN** (Logical Cluster Number of $MFT) | `0x214A`           |
| **`+0x48`**         | **8** | **Volume Serial Number**                     | `504D550C97550C3C` |

```js
const partStart = firstLBA * 512; // = 0x10000
const backupVBR = partStart + (lastLBA - firstLBA) * 512; // = 0x63EFE00
const bvbr = d.subarray(backupVBR, backupVBR + 512);

const bps = bvbr.readUInt16LE(0x0b); // 512
const spc = bvbr[0x0d]; // 8
const mftLCN = Number(bvbr.readBigUInt64LE(0x30)); // 0x214A
const volSer = bvbr.subarray(0x48, 0x50); // 8 bytes raw
```

> **Volume Serial Number** is a value **uniquely tied to this volume** — randomly generated at format time. It will reappear in Phase 3 (key derivation). **Remember the 8 raw bytes** in their exact on-disk order (little-endian raw, NOT the format `fsutil` displays).

> Appears in the ransom note (hint):

```
Your personal installation key:
504D550C97550C3C
```

### Finding Fragment 2 — XOR in VBR Slack

> From the ransom note (hint):

```
Crypto wallet address:
+0x80??�??�?s�m�thi�g_wr�ng
```

In the "slack" area (unused space) of the backup VBR, at offset `+0x80` from the start of the VBR, there is a chunk of data **XORed** with the Volume Serial:

```js
// Read 32 bytes at backupVBR + 0x80
const xoredData = d.subarray(backupVBR + 0x80, backupVBR + 0x80 + 32);

// XOR with volume serial (8 bytes, repeating cycle)
const serial = volSer; // 8 bytes raw from VBR+0x48
const result = Buffer.from(
	xoredData.map((b, i) => b ^ serial[i % serial.length]),
);
// → "f2{ca52-4285}\x00\x00..."
```

> **Why the `f2{}` marker?** Because Ellie mentioned on Discord that frag 2 and frag 3 have markers 🐸

Strip the marker: extract the content between `f2{` and `}`:

**🏴 Fragment 2:** `ca52-4285`

## Phase 3 — Reverse Engineer Encryptor + AES Decryption → Fragment 3

> This phase looks like the hardest but is actually free points.
> You need to **reverse engineer** the `encryptor.exe` file (native C++ x64 binary) to understand the encryption algorithm, then decrypt an MFT record.
> However, Ellie compiled it without any optimization flags, so the IDA decompiler output is essentially usable as-is. You could even feed it to an AI and it would rewrite the entire source code...

### Theory — What is MFT?

> **MFT** (Master File Table) is the "heart" of NTFS. Every file/directory on disk has an **MFT record** (1024 bytes), containing metadata and data (if small) or pointers to on-disk data (data-runs if the file is large).
>
> Each record starts with the magic `FILE` (4 bytes: `46 49 4C 45`).
>
> Absolute offset of the MFT on disk:
>
> ```
> mftByte = partStart + MFT_LCN × SectorsPerCluster × BytesPerSector
>         = 0x10000 + 0x214A × 8 × 512
>         = 0x215A000
> ```

### What Does the Encryptor Do?

Reversing the binary with Ghidra/IDA reveals the encryptor performs **3 destructive steps**:

1. **Encrypts the MFT record** of `flag.zip` with AES-256-CBC
2. **Overwrites the VBR** with a ransom note (read from `note.txt`, replacing `{SERIAL}` with the serial hex)
3. **Zeros the GPT Primary Header** (LBA1)

Only **one single record** is encrypted — the record for `flag.zip`. Once encrypted, the `FILE` magic disappears → the NTFS driver can't recognize it → the file "vanishes."

### Key Derivation Algorithm

This is the core part to reverse:

```
key = SHA-256( PRNG(SEED).NextBytes(32)  ‖  SALT  ‖  volSerial )
```

Where:

- **`‖`** = concatenation — joining byte arrays together
- **`SEED`** = `956377` — a hardcoded constant in the binary, randomly chosen by Ellie
- **`SALT`** = `"yuneko_dev_"` — an ASCII string, 11 bytes, hardcoded in the binary
- **`volSerial`** = 8 raw bytes at `VBR+0x48` (obtained in Phase 2)
- **`PRNG`** = .NET legacy pseudo-random number generator
- **`SHA-256`** = hash function, outputs 32 bytes = AES-256 key

#### .NET Legacy PRNG (reimplemented in Node.js)

The encryptor is written in C++ but reuses the **subtractive PRNG** algorithm identical to .NET Framework's `System.Random`. Reimplementation:

```js
const MBIG = 2147483647,
	MSEED = 161803398;
class NetRandom {
	constructor(seed) {
		this.s = new Array(56).fill(0);
		let sub = seed === -2147483648 ? MBIG : Math.abs(seed);
		let mj = MSEED - sub;
		this.s[55] = mj;
		let mk = 1;
		for (let i = 1; i < 55; i++) {
			const ii = (21 * i) % 55;
			this.s[ii] = mk;
			mk = mj - mk;
			if (mk < 0) mk += MBIG;
			mj = this.s[ii];
		}
		for (let k = 0; k < 4; k++)
			for (let i = 1; i < 56; i++) {
				this.s[i] -= this.s[1 + ((i + 30) % 55)];
				if (this.s[i] < 0) this.s[i] += MBIG;
			}
		this.inext = 0;
		this.inextp = 21;
	}
	samp() {
		this.inext = this.inext + 1 >= 56 ? 1 : this.inext + 1;
		this.inextp = this.inextp + 1 >= 56 ? 1 : this.inextp + 1;
		let r = this.s[this.inext] - this.s[this.inextp];
		if (r === MBIG) r--;
		if (r < 0) r += MBIG;
		this.s[this.inext] = r;
		return r;
	}
	nextBytes(n) {
		return Buffer.from(Array.from({ length: n }, () => this.samp() % 256));
	}
}
```

#### Complete Key Derivation Process

```js
const crypto = require('crypto');

// Step 1: PRNG output (32 bytes) — always identical because the seed is fixed
const rb = new NetRandom(956377).nextBytes(32); // 32 deterministic bytes

// Step 2: Concatenate: rb + SALT + volSerial
const SALT = Buffer.from('yuneko_dev_', 'ascii');
const volSerial = volSer; // 8 bytes raw from VBR+0x48
const payload = Buffer.concat([rb, SALT, volSerial]); // 32 + 11 + 8 = 51 bytes

// Step 3: SHA-256
const key = crypto.createHash('sha256').update(payload).digest();
// → A558D6CF73F2ABA9007595818EBD0C727DB7B2C941520360FFE1B724621BB89C
```

> **`volSerial` must be the 8 RAW bytes** — in exact on-disk order at `VBR+0x48`. **Not** a hex-string, not the format `fsutil` displays (which reverses byte order and adds dashes).

### Locating the Encrypted Record — Two Traps

**Trap 1:** Don't scan for the string `"flag.zip"` in the MFT and try to decrypt that. The real record has been AES-encrypted → the `"flag.zip"` string inside has become garbage → **you can't find it by scanning**. The occurrence you see is in a different record (the parent directory).

**Trap 2:** `"flag.zip"` (in UTF-16LE) appears in **TWO** MFT records:

1. **Parent directory record** (`Backup\`): only has `$INDEX_ROOT` attribute (type `0x90`) — contains the directory file listing
2. **Actual file record** (`flag.zip`): has `$DATA` attribute (type `0x80`) — contains data-runs pointing to file content

→ You must pick the record with **`$DATA` (0x80)**. Picking the directory record → Phase 4 loses its data-runs.

**Correct locating strategy:**

The encrypted record **lost its `FILE` magic** (first 4 bytes became garbage). Strategy:

```
1. Scan the MFT in 1024-byte steps (one record each)
2. Skip blocks starting with "FILE" (intact records, not the target)
3. Skip all-zero blocks (empty space)
4. For each remaining block, try AES decryption
5. If the result starts with "FILE" + contains "flag.zip" (UTF-16) + has $DATA → FOUND!
```

```js
const mftByte = partStart + mftLCN * spc * bps; // = 0x215A000
const REC = 1024;
const FILE_MAGIC = Buffer.from('FILE', 'latin1');
const flagU16 = Buffer.from('flag.zip', 'utf16le');

const decRec = (buf) => {
	const c = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
	c.setAutoPadding(false);
	return Buffer.concat([c.update(buf), c.final()]);
};

// Check if the record has a $DATA attribute (0x80)
// → distinguishes the flag.zip file record from the parent directory record
const recHasData = (r) => {
	let a = r.readUInt16LE(0x14);
	while (a + 8 <= REC) {
		const t = r.readUInt32LE(a);
		if (t === 0xffffffff) break;
		const len = r.readUInt32LE(a + 4);
		if (len <= 0 || a + len > REC) break;
		if (t === 0x80) return true;
		a += len;
	}
	return false;
};

let recAbs = -1,
	rec = null;
for (let off = mftByte; off + REC <= mftByte + 8 * 1024 * 1024; off += REC) {
	const blk = d.subarray(off, off + REC);
	if (blk.subarray(0, 4).equals(FILE_MAGIC)) continue; // intact record, skip
	if (blk.every((b) => b === 0)) continue; // empty, skip

	let cand;
	try {
		cand = decRec(blk);
	} catch {
		continue;
	}
	if (!cand.subarray(0, 4).equals(FILE_MAGIC)) continue;

	const cfx = applyFixup(Buffer.from(cand));
	if (cfx.indexOf(flagU16) >= 0 && recHasData(cfx)) {
		recAbs = off; // FOUND! offset = 0x216C800
		rec = cand;
		break;
	}
}
```

> **AES-256-CBC, IV = 16 bytes `0x00`, NO padding:** AES-CBC (Cipher Block Chaining) encrypts each 16-byte block, XORing with the previous block's ciphertext. The IV (Initialization Vector) initializes the first block. Here IV = zero. "NO padding" means the input must be a multiple of 16 bytes — a 1024-byte record = 64 AES blocks, evenly divisible → no padding needed.

### Reading Fragment 3 from the Decrypted Record

After decrypting the AES-encrypted record back to a clean `FILE` record, fragment 3 is hidden in the **record slack** — the area after the **end-marker `FF FF FF FF`** in the attribute list.

> **Theory — NTFS Attribute List:** Each MFT record contains a sequence of attributes (`$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA`, ...). The end of the list is marked by `0xFFFFFFFF` (4 bytes of `FF`). From this marker to the end of the 1024-byte record is **slack space** — unused space that may contain leftover data from old records or... a flag fragment hidden deliberately.

```js
// Find end-marker FFFFFFFF (start searching from offset 0x30 to skip the header)
const mk3 = recFx.indexOf(Buffer.from([0xff, 0xff, 0xff, 0xff]), 0x30);

// Fragment 3 is at marker + 8 bytes (skip 4-byte marker + 4-byte padding)
const win3 = recFx.toString('latin1', mk3 + 8, mk3 + 8 + 32);
// → "f3{-844a-ca0}\x00..."
const m3 = win3.match(/f3\{([^}]*)\}/)[1]; // → "-844a-ca0"
```

Strip the `f3{` and `}` markers:

**🏴 Fragment 3:** `-844a-ca0`

---

## Phase 4 — Anti-carve (data-runs) + ZipCrypto → Fragment 4

### Why Can't You Carve It?

`flag.zip` is a **LIVE** file (not deleted) but is **heavily fragmented** — 59 fragments on disk.

> **Fragmentation:** When NTFS can't find a contiguous region large enough, it splits the file into multiple chunks (fragments/extents) scattered across the disk. Each chunk is at a different location.

Linear carving tools (binwalk, foremost, photorec) work on the principle of:

1. Find the magic `PK\x03\x04` (zip header)
2. Read contiguously from there to the end

But since the file is fragmented, **data from other files** sits between the fragments → linear carving swallows garbage into the middle → corrupted zip.

**The only way:** Read according to the **data-runs** — a list of instructions in the MFT record specifying which cluster each fragment lives at and how many clusters long it is.

### Theory — NTFS Data Runs

For **non-resident** files (large files with data stored outside the MFT record), the `$DATA` attribute (type `0x80`) contains a **data-run list** — a compressed byte sequence describing fragment locations:

```
Each data-run entry:
  [header byte] [length bytes...] [offset bytes...]

  header = (offsetSize << 4) | lengthSize
  - lengthSize = header & 0x0F  → number of bytes encoding "cluster count"
  - offsetSize = header >> 4    → number of bytes encoding "offset from previous run" (signed!)

  length = number of consecutive clusters in this fragment
  offset = LCN (Logical Cluster Number) distance from previous fragment (signed, can be negative!)

  Absolute LCN = previous_LCN + offset (cumulative sum)

  End marker: header byte = 0x00
```

```js
// Parse data-runs from the decrypted record
function dataRuns(r) {
	// Find $DATA attribute (type 0x80), non-resident (flag byte = 1)
	let a = r.readUInt16LE(0x14); // first attribute offset
	while (a + 4 <= REC) {
		const type = r.readUInt32LE(a);
		if (type === 0xffffffff) break;
		const len = r.readUInt32LE(a + 4);
		if (len <= 0 || a + len > REC) break;

		if (type === 0x80 && r[a + 8] === 1) {
			// $DATA, non-resident
			const runOff = r.readUInt16LE(a + 0x20);
			const realSize = Number(r.readBigUInt64LE(a + 0x30));

			let p = a + runOff,
				lcn = 0,
				runs = [];
			while (r[p] !== 0) {
				const h = r[p++];
				const lenSz = h & 0x0f;
				const offSz = h >> 4;

				let cnt = 0;
				for (let i = 0; i < lenSz; i++) cnt += r[p++] * 2 ** (8 * i);
				let off = 0;
				for (let i = 0; i < offSz; i++) off += r[p++] * 2 ** (8 * i);
				if (offSz > 0 && r[p - 1] & 0x80) off -= 2 ** (8 * offSz); // sign-extend

				lcn += off;
				runs.push([lcn, cnt]);
			}
			return { runs, realSize };
		}
		a += len;
	}
	return null;
}
```

### ⚠️ Trap: NTFS Fixup (Update Sequence Array)

This is an **extremely subtle** trap that many solvers fell into.

> **Theory — NTFS Update Sequence Array (USA):**
>
> Each MFT record is 1024 bytes = 2 sectors (512 bytes each). NTFS uses a **fixup** mechanism to detect bad sectors: the **last 2 bytes of each sector** (offsets `0x1FE` and `0x3FE` within the record) on disk are **replaced** by the **USN (Update Sequence Number)** — a check value.
>
> The **real** bytes (that were overwritten) are stored in the **USA** (Update Sequence Array) in the record header.
>
> ```
> Record header:
>   +0x04 (2 bytes): USA offset (starting position of USA within the record)
>   +0x06 (2 bytes): USA count (= number of sectors + 1 = 3)
>
> USA layout (6 bytes):
>   [USN (2 bytes)] [real bytes sector 0 (2 bytes)] [real bytes sector 1 (2 bytes)]
>
> On disk:
>   record[0x1FE..0x1FF] = USN (NOT real data!)
>   record[0x3FE..0x3FF] = USN (NOT real data!)
>
> Restoration:
>   record[0x1FE..0x1FF] = USA[2..3]   (real bytes for sector 0)
>   record[0x3FE..0x3FF] = USA[4..5]   (real bytes for sector 1)
> ```

**Why is this a trap?** When the data-run list is long (59 fragments!), it can **span across** offset `0x1FE` or `0x3FE`. If the parser reads raw bytes without applying fixup → the 2 bytes at sector boundaries are **USN check values** instead of actual data-run bytes → the parsed cluster numbers/offsets are **completely wrong** → the reassembled zip is corrupted → unzip fails.

```js
// Apply fixup BEFORE parsing data-runs
function applyFixup(r) {
	const usaOff = r.readUInt16LE(0x04);
	const usaCnt = r.readUInt16LE(0x06);

	for (let i = 1; i < usaCnt; i++) {
		const sectorEnd = i * 512 - 2; // position of last 2 bytes of each sector
		// Overwrite on-disk bytes (USN) with real bytes from USA
		r.writeUInt16LE(r.readUInt16LE(usaOff + i * 2), sectorEnd);
	}
	return r;
}
```

> **Valid "lazy" approach:** If you've restored the GPT header (copy backup → primary, patch MyLBA/AltLBA/CRC32) + VBR (copy backup → main), the disk **becomes mountable**. The NTFS driver handles fixup + data-runs automatically → just **copy `flag.zip`** via Explorer or use TSK:
>
> ```bash
> mmls infected.vhd           # list partitions
> fls -o <sector> -r infected.vhd | grep flag
> icat -o <sector> infected.vhd <inode> > flag.zip
> ```

### Reassembling flag.zip from Data-Runs

```js
// Reassemble file from data-runs
const clusterSize = spc * bps; // = 8 × 512 = 4096 bytes
const dr = dataRuns(recFx);

const parts = dr.runs.map(([lcn, cnt]) => {
	const start = partStart + lcn * clusterSize;
	return d.subarray(start, start + cnt * clusterSize);
});

const zipBuf = Buffer.concat(parts).subarray(0, dr.realSize); // trim trailing cluster padding
// zipBuf.length = 5,021,588 bytes → intact flag.zip
require('fs').writeFileSync('flag_recovered.zip', zipBuf);
```

### Opening flag.zip — ZipCrypto

`flag.zip` is encrypted with **ZipCrypto** (PKWARE traditional encryption) — a classic, weak encryption algorithm, but sufficient for CTF purposes.

**Password = AES key from Phase 3** (hex string, **UPPERCASE**):

```
A558D6CF73F2ABA9007595818EBD0C727DB7B2C941520360FFE1B724621BB89C
```

```bash
7z x -pA558D6CF73F2ABA9007595818EBD0C727DB7B2C941520360FFE1B724621BB89C flag.zip
# or:
unzip -P A558D6CF73F2ABA9007595818EBD0C727DB7B2C941520360FFE1B724621BB89C flag.zip
```

> **Why not brute-force / bkcrack?** ZipCrypto is vulnerable to **known-plaintext** attacks via `bkcrack` — if you know ≥12 consecutive bytes of plaintext. But the files inside the zip are all high-entropy media (.ogg, .mp4, .mid) → no known-plaintext → bkcrack is useless. The only path: RE the encryptor → get the key.

After extraction, read `part4.txt`:

**🏴 Fragment 4:** `a5699a9cd}`

---

## Assembling the Flag

Strip the markers and concatenate the 4 fragments in order:

| Phase | Raw                          | After stripping marker | Fragment            |
| ----- | ---------------------------- | ---------------------- | ------------------- |
| 1     | `base64 → LYKNCTF{7f87f117-` | —                      | `LYKNCTF{7f87f117-` |
| 2     | `f2{ca52-4285}`              | `ca52-4285`            | `ca52-4285`         |
| 3     | `f3{-844a-ca0}`              | `-844a-ca0`            | `-844a-ca0`         |
| 4     | `a5699a9cd}`                 | —                      | `a5699a9cd}`        |

```
p1 + p2 + p3 + p4
= "LYKNCTF{7f87f117-" + "ca52-4285" + "-844a-ca0" + "a5699a9cd}"
= LYKNCTF{7f87f117-ca52-4285-844a-ca0a5699a9cd}
```

Verify: `7f87f117-ca52-4285-844a-ca0a5699a9cd` is a valid UUID v4 (format `8-4-4-4-12`). ✅

---

## 🏁 FLAG

```
LYKNCTF{7f87f117-ca52-4285-844a-ca0a5699a9cd}
```
