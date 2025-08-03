import secrets
from secretsharing import PlaintextToHexSecretSharer
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# === Key Generation Functions ===

def generate_transaction_key():
    """Generates a 256-bit transaction key."""
    return secrets.token_hex(32)  # 32 bytes (256 bits)

def split_key(key, num_shares=5, threshold=3):
    """Split the transaction key into shares using Shamir's Secret Sharing."""
    return PlaintextToHexSecretSharer.split_secret(key, threshold, num_shares)

def reconstruct_key(shares):
    """Reconstruct the transaction key from the given shares."""
    return PlaintextToHexSecretSharer.recover_secret(shares)

def encrypt_share(share, public_key):
    """Encrypt a key share using RSA encryption with OAEP padding."""
    return public_key.encrypt(
        share.encode(),  # Convert share to bytes before encrypting
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def load_public_key_from_pem(pem_data):
    """Load a public key from PEM format."""
    return serialization.load_pem_public_key(pem_data.encode())
