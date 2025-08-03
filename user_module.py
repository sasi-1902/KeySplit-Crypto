import hashlib
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_user_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def register_user(name, user_id, password):
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    private_key, public_key = generate_user_keys()

    # Save user data in a pickle file
    user_data = {
        "name": name,
        "id": user_id,
        "password_hash": password_hash,
        "public_key": public_key,
        "private_key": private_key
    }
    with open(f"user_{user_id}.pkl", "wb") as f:
        pickle.dump(user_data, f)

    # Save public/private keys to PEM files
    with open(f"{user_id}_private.pem", "wb") as f:
        f.write(private_key)
    with open(f"{user_id}_public.pem", "wb") as f:
        f.write(public_key)

def authenticate_user(user_id, password):
    try:
        with open(f"user_{user_id}.pkl", "rb") as f:
            user_data = pickle.load(f)
        return hashlib.sha256(password.encode()).hexdigest() == user_data["password_hash"]
    except FileNotFoundError:
        return False
