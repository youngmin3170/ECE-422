import sys

def wha(data):

    MASK = 0x3FFFFFFF
    out_hash = 0
    for b in data:
        iv = ((b ^ 0xCC) << 24) | ((b ^ 0x33) << 16) | ((b ^ 0xAA) << 8) | (b ^ 0x55)
        out_hash = ((out_hash & MASK) + (iv & MASK))
    return out_hash & 0xFFFFFFFF



in_path, out_path = sys.argv[1], sys.argv[2]
with open(in_path, 'rb') as f:
    data = f.read()
h = wha(data)
with open(out_path, 'w') as g:
    g.write(f"{h:08x}")

print(f"WHA hash written to {out_path}")

