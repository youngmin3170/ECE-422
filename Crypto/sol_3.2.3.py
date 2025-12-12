import urllib.request
import urllib.error

with open('3.2.3_ciphertext.hex', 'r') as f:
    ciphertext_hex = f.read().strip()

ciphertext = bytes.fromhex(ciphertext_hex)

IV = ciphertext[:16]
ct_blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]

def oracle(data_hex):
    url = f'http://72.36.89.21:8080/mp3/yj21/?{data_hex}'
    try:
        urllib.request.urlopen(url, timeout=10)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True
        return False
    except Exception as e:
        print(f"Oracle error: {e}")
        return False

def decrypt_all():
    all_blocks = [IV] + ct_blocks
    plaintext_blocks = []

    for i in range(len(ct_blocks)):
        print(f"Decrypting block {i+1} / {len(ct_blocks)}")
        
        prefix_blocks = all_blocks[:i]
        prev_block = all_blocks[i]
        curr_block = all_blocks[i + 1]

        plaintext_block = decrypt_block(prefix_blocks, prev_block, curr_block)
        
        plaintext_blocks.append(plaintext_block)

    full_plaintext = b''.join(plaintext_blocks)
    return full_plaintext

def decrypt_block(prefix_blocks, prev_block, curr_block):
    
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    for pad_len in range(1, 17):
        target_padding_byte = 16

        modified_prev = bytearray(prev_block)
        
        j_attack = 16 - pad_len

        for k in range(j_attack + 1, 16): 
            desired_value = 16 - (k - j_attack)
            modified_prev[k] = intermediate[k] ^ desired_value

        found = False
        for guess in range(256):
            modified_prev[j_attack] = guess

            save_byte = None
            if pad_len < 16:
                save_byte = modified_prev[j_attack - 1]
                modified_prev[j_attack - 1] = (modified_prev[j_attack - 1] + 1) % 256

            payload_blocks = prefix_blocks + [bytes(modified_prev)] + [bytes(curr_block)]
            test_ct = b''.join(payload_blocks)

            is_valid = oracle(test_ct.hex())

            if save_byte is not None:
                modified_prev[j_attack - 1] = save_byte

            if is_valid:
                intermediate[j_attack] = guess ^ target_padding_byte
                plaintext[j_attack] = intermediate[j_attack] ^ prev_block[j_attack]
                found = True
                break

        if not found:
            intermediate[j_attack] = 0
            plaintext[j_attack] = 0

    return bytes(plaintext)

def strip_custom_padding(msg):
    
    if len(msg) == 0:
        return msg

    last_byte = msg[-1]
    if last_byte > 16:
        return msg 

    padlen = 17 - last_byte

    if padlen > len(msg):
        return msg

    expected_padding = bytes(range(16, 16 - padlen, -1))
    if msg[-padlen:] == expected_padding:
        return msg[:-padlen]

    return msg

if __name__ == '__main__':

    decrypted = decrypt_all()

    plaintext = strip_custom_padding(decrypted)
    
    print(plaintext.decode('utf-8', errors='replace'))

    with open('sol_3.2.3.txt', 'w') as f:
        f.write(plaintext.decode('utf-8', errors='replace'))

    print("\nSaved to sol_3.2.3.txt")
