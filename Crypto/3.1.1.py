# import sys

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: py 3.1.1.py <input_file>")
#         sys.exit(1) 

#     input_file_path = sys.argv[1]

#     with open(input_file_path, "r") as file:
#         file_content = file.read().strip()
    
#     integer_parsed = int(file_content, 16)
#     decimal_output = str(integer_parsed)
#     binary_output = bin(integer_parsed)[2:]

#     decimal_output_path = "sol_3.1.1_decimal.txt"
#     binary_output_path = "sol_3.1.1_binary.txt"

#     with open(decimal_output_path, "w") as file:
#         file.write(decimal_output)

#     with open(binary_output_path, "w") as file:
#         file.write(binary_output)
    
#     print("Conversion completed successfully.")

# 3.1.4
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct = bytes.fromhex("ccfb8d74dea4f7b8de64c23164055531e46e91cd35eb808b717b71bddc10b4481ba45ca06cec2a631c80370703a5c5d7285da38bc3c870c5bd4c5544691eaea72d8b2fd4af61cf92b8ce890081f8fb09")
iv = bytes(16)
key = bytes(32)   # 32 zero bytes = all-zero key

pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
try:
    pt = unpad(pt, 16)
except Exception:   
    pass

print(pt.decode('utf-8', errors='replace'))



