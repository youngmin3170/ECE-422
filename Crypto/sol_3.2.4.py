import math
import pbp
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse


with open('moduli.hex', 'r') as f:
    lines = f.readlines()
moduli = [int(line.strip(), 16) for line in lines]

with open('3.2.4_ciphertext.enc.asc', 'r') as f:
    ciphertext = f.read()

e = 65537
found_key = False
    
for i in range(len(moduli)):
    if found_key:
        break
        
    N = moduli[i]
    
    if i % 100 == 0:
        print(f"Checking modulus {i}/{len(moduli)}...")

    for j in range(i + 1, len(moduli)):
        N_j = moduli[j]
        
        p = math.gcd(N, N_j)
        
        if p > 1:
                            
            for key_index, N_key in [(i, N), (j, N_j)]:
                
                if N_key % p != 0:
                    continue 

                try:
                    q = N_key // p
                    if p * q != N_key:
                        continue
                        
                    phi = (p - 1) * (q - 1)
                    
                    if math.gcd(e, phi) != 1:
                        continue

                    d = inverse(e, phi)
                    
                    rsakey = RSA.construct((N_key, e, d, p, q))
                    
                    plaintext = pbp.decrypt(rsakey, ciphertext)
                                            
                    final_text = plaintext.decode('latin-1', errors='replace')
                    
                    with open('sol_3.2.4.txt', 'w') as f:
                        f.write(final_text)
                    print("Saved plaintext to sol_3.2.4.txt")
                    
                    found_key = True
                    break
                
                except Exception as ex:
                    continue
            
            if found_key:
                break

