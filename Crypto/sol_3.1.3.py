import sys
from Crypto.Cipher import AES


if len(sys.argv) != 5:
    print("Usage: python3 sol_3.1.3.py <ciphertext_file> <key_file> <iv_file> <output_file>")
    sys.exit(1)


with open(sys.argv[1], 'r') as f:
    ciphertext = bytes.fromhex(f.read().strip())
with open(sys.argv[2], 'r') as f:
    key = bytes.fromhex(f.read().strip())
with open(sys.argv[3], 'r') as f:
    iv = bytes.fromhex(f.read().strip())

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)


with open(sys.argv[4], 'wb') as f:
    f.write(plaintext)

print("Decryption complete. Plaintext written to", sys.argv[4])



