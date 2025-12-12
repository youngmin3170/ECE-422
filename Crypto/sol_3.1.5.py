import sys

if len(sys.argv) != 5:
    print("expected: python3 sol_3.1.5.py ciphertext_file key_file modulo_file output_file")
    sys.exit(1)

ciphertext_file, key_file, modulo_file, output_file = sys.argv[1:]

with open(ciphertext_file) as f:
    c = int(f.read().strip(), 16)
with open(key_file) as f:
    d = int(f.read().strip(), 16)
with open(modulo_file) as f:
    n = int(f.read().strip(), 16)

m = pow(c, d, n)
with open(output_file, "w") as f:
    f.write(f"{m:x}\n")
