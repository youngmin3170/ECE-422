"""
from hashlib import sha256

my_hash = sha256(blob.encode('latin-1')).hexdigest()

if my_hash == "506ce547eac9c5a8c7f06daa0cd9006e6d44f90c27acfb8f2d5f9558316e2e23":
    print("I come in peace.")
else:
    print("Prepare to be destroyed!")