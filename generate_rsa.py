from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

# Directory to save keys
KEYS_DIR = 'generated_keys'

# Ensure the directory exists
os.makedirs(KEYS_DIR, exist_ok=True)

# Function to generate RSA keys
def generate_rsa_keys(user_id):
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate public key from private key
        public_key = private_key.public_key()
        
        # Save private key to PEM file
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Save public key to PEM file
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_key_filename = os.path.join(KEYS_DIR, f"{user_id}_private.pem")
        public_key_filename = os.path.join(KEYS_DIR, f"{user_id}_public.pem")
        
        # Write private and public keys to files
        with open(private_key_filename, 'wb') as private_file:
            private_file.write(private_pem)
        
        with open(public_key_filename, 'wb') as public_file:
            public_file.write(public_pem)

        print(f" Keys generated for {user_id}:")
        print(f"  Private Key: {private_key_filename}")
        print(f"  Public Key: {public_key_filename}")

    except Exception as e:
        print(f" Error generating keys for {user_id}: {e}")

# Generate keys for 5 users (user1, user2, ..., user5)
for i in range(1, 6):
    user_id = f"user{i}"
    generate_rsa_keys(user_id)
