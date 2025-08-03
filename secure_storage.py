# secure_storage.py

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

# Store encrypted shares
def encrypt_and_store_share(share, public_key):
    encrypted_share = public_key.encrypt(
        share.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Store the encrypted share in a secure manner
    with open("encrypted_share.bin", "wb") as f:
        f.write(encrypted_share)

# Retrieve and decrypt share
def decrypt_share(encrypted_share, private_key):
    decrypted_share = private_key.decrypt(
        encrypted_share,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_share.decode()
