import argparse, string
from collections import Counter

ALPHABET = string.ascii_uppercase
A_ORD = ord('A')

def read_text(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def ref_freqs(text):
    cnt = Counter(c for c in text if c in ALPHABET)
    total = sum(cnt.values())
    return {ch: cnt.get(ch, 0) / total for ch in ALPHABET}

def ioc(chunk_letters):
    n = len(chunk_letters)
    if n <= 1: 
        return 0.0
    cnt = Counter(chunk_letters)
    return sum(v*(v-1) for v in cnt.values()) / (n*(n-1))

def avg_ioc(cipher_letters, keylen):
    chunks = [[] for _ in range(keylen)]
    for i, ch in enumerate(cipher_letters):
        chunks[i % keylen].append(ch)
    vals = [ioc(ch) for ch in chunks if len(ch) > 0]
    return sum(vals) / len(vals) if vals else 0.0

def chi2(observed_counts, expected_freqs, n):
    chi = 0.0
    eps = 1e-12
    for ch in ALPHABET:
        o = observed_counts.get(ch, 0)
        e = expected_freqs[ch] * n
        if e < eps:
            continue
        chi += (o - e) ** 2 / e
    return chi

def recover_key(cipher_letters, keylen, freqs):
    chunks = [[] for _ in range(keylen)]
    for i, ch in enumerate(cipher_letters):
        chunks[i % keylen].append(ch)

    key_shifts = []
    for k in range(keylen):
        chunk = chunks[k]
        n = len(chunk)
        if n == 0:
            key_shifts.append(0)
            continue
        best_s, best_c = 0, float('inf')
        for s in range(26):
            dec = [chr(((ord(c) - A_ORD - s) % 26) + A_ORD) for c in chunk]
            obs = Counter(dec)
            stat = chi2(obs, freqs, n)
            if stat < best_c:
                best_c, best_s = stat, s
        key_shifts.append(best_s)
    return ''.join(chr(A_ORD + s) for s in key_shifts)

def decrypt_keep_nonletters(ciphertext, key):
    out, ki, klen = [], 0, len(key)
    kvals = [ord(k) - A_ORD for k in key]
    for ch in ciphertext:
        up = ch.upper()
        if up in ALPHABET:
            c = ord(up) - A_ORD
            p = (c - kvals[ki % klen]) % 26
            out.append(chr(p + A_ORD))
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cipher_file")
    ap.add_argument("reference_file")
    ap.add_argument("output_file")
    args = ap.parse_args()

    ciphertext = read_text(args.cipher_file)
    reftext = read_text(args.reference_file)
    freqs = ref_freqs(reftext)

    cipher_letters = [c for c in ciphertext if c in ALPHABET]
    
    best_L, best_v = 1, -1.0
    table = []
    for L in range(1, 31):
        v = avg_ioc(cipher_letters, L)
        table.append((L, v))
        if v > best_v:
            best_v, best_L = v, L

    key = recover_key(cipher_letters, best_L, freqs)
    plaintext = decrypt_keep_nonletters(ciphertext, key)

    with open(args.output_file, "w", encoding="utf-8") as f:
        f.write(plaintext)

    print("Estimated key length:", best_L)
    print("Estimated key:", key)
    print("Wrote plaintext to:", args.output_file)

if __name__ == "__main__":
    main()
