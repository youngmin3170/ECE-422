import sys
from urllib.parse import quote_from_bytes
from pymd5 import md5, padding

KEY_LEN = 8

def main():
    if len(sys.argv) != 4:
        print("usage: python3 sol_3.2.1.py query_file command3_file output_file")
        sys.exit(1)

    qfile, cmdfile, outfile = sys.argv[1:4]
    query = open(qfile, "rb").read().strip()
    suffix = open(cmdfile, "rb").read().strip()

    token_hex = query[6:6+32].decode()
    orig = query[6+33:]

    bits_before = (KEY_LEN + len(orig)) * 8
    glue = padding(bits_before)
    total_bits = bits_before + len(glue) * 8

    h = md5(state=token_hex, count=total_bits)
    h.update(suffix)
    new_token = h.hexdigest()

    glue_enc = quote_from_bytes(glue)

    forged = b"token=" + new_token.encode() + b"&" + orig + glue_enc.encode() + suffix

    with open(outfile, "wb") as f:
        f.write(forged)

    print("done")

if __name__ == "__main__":
    main()
