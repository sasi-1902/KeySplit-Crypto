import secrets
import time
import uuid
import os
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from typing import List, Tuple
from logging_utils import setup_logging, log_transaction  # 🔗 logging setup
from security_utils import secure_wipe


# === Setup Logging ===
setup_logging()

# === Phase 1: Key Generation, Split & Encrypt Shares ===

def generate_transaction_key() -> str:
    return secrets.token_hex(32)

# Custom Shamir's Secret Sharing implementation
_PRIME = (1 << 521) - 1

def split_key(secret_hex: str, num_shares: int = 5, threshold: int = 3) -> List[str]:
    secret_int = int(secret_hex, 16)
    coeffs = [secret_int] + [secrets.randbelow(_PRIME) for _ in range(threshold - 1)]

    def _poly(x: int) -> int:
        res = 0
        for power, coef in enumerate(coeffs):
            res = (res + coef * pow(x, power, _PRIME)) % _PRIME
        return res

    shares = []
    for i in range(1, num_shares + 1):
        y = _poly(i)
        shares.append(f"{i}-{y:x}")
    return shares

def reconstruct_key(shares: List[str]) -> str:
    points: List[Tuple[int,int]] = []
    for share in shares:
        x_str, y_hex = share.split("-")
        points.append((int(x_str), int(y_hex, 16)))

    def _lagrange(x: int) -> int:
        total = 0
        for j, (xj, yj) in enumerate(points):
            num = 1
            den = 1
            for m, (xm, _) in enumerate(points):
                if m != j:
                    num = (num * (x - xm)) % _PRIME
                    den = (den * (xj - xm)) % _PRIME
            total = (total + yj * num * pow(den, -1, _PRIME)) % _PRIME
        return total

    secret_int = _lagrange(0)
    return f"{secret_int:x}"

def encrypt_share(share: str, pub_key) -> bytes:
    return pub_key.encrypt(
        share.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# === Signing / Verification ===

def generate_nonce() -> str:
    return str(uuid.uuid4())

def sign_request(user_id: str, priv_key) -> dict:
    nonce = generate_nonce()
    ts = int(time.time())
    msg = f"{user_id}:{nonce}:{ts}".encode()
    sig = priv_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    return {"message": msg, "signature": sig}

def verify_response(resp: dict, pub_key) -> bool:
    try:
        pub_key.verify(resp['sig'], resp['share'].encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception as e:
        log_transaction(resp['entity'], "Verify Share", f"Failed - {e}")
        return False

# === PEM Loaders ===

def load_private_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

# === Parallel Share Request ===

def request_shares_parallel(user_id: str, user_priv, entities: list, encrypted_shares: dict) -> list:
    def proc(ent):
        eid = ent['id']
        sign_request(user_id, user_priv)

        share_plain = ent['private_key'].decrypt(
            encrypted_shares[eid],
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode()

        sig = ent['private_key'].sign(share_plain.encode(), padding.PKCS1v15(), hashes.SHA256())
        return {'entity': eid, 'share': share_plain, 'sig': sig}

    with ThreadPoolExecutor() as exe:
        return list(exe.map(proc, entities))

# === Main Execution ===

if __name__ == '__main__':
    user_id = 'test123'
    user_priv = load_private_key(f'{user_id}_private.pem')
    log_transaction(user_id, "Load Private Key", "Success")

    entities = []
    for i in range(1, 6):
        eid = f'user{i}'
        priv = load_private_key(f'{eid}_private.pem')
        pub = load_public_key(f'{eid}_public.pem')
        entities.append({'id': eid, 'private_key': priv, 'public_key': pub})
        log_transaction(eid, "Load Keys", "Success")

    tx_key = generate_transaction_key()
    shares = split_key(tx_key)
    encrypted_shares = {e['id']: encrypt_share(sh, e['public_key']) for e, sh in zip(entities, shares)}
    log_transaction(user_id, "Generate and Encrypt Shares", "Success")

    print(f'Generated TX key: {tx_key}')
    print(f'Plain shares:      {shares}\n')

    responses = request_shares_parallel(user_id, user_priv, entities, encrypted_shares)
    print('Responses collected:')
    for r in responses:
        print(f'  {r["entity"]}: {r["share"]}')
        log_transaction(r["entity"], "Respond with Share", "Received")

    valid = []
    for r in responses:
        if r['entity'] in ['user1', 'user2']:
            if verify_response(r, next(e['public_key'] for e in entities if e['id'] == r['entity'])):
                valid.append(r)
                log_transaction(r['entity'], "Verify Response", "Valid")
        else:
            log_transaction(r['entity'], "Verify Response", "Simulated Failure")

    if len(valid) < 3:
        print(f'\n🚫 Threshold not met: Only {len(valid)} valid shares available.')
        log_transaction(user_id, "Reconstruct Key", "Failed - Threshold not met")
    else:
        rec = reconstruct_key([v['share'] for v in valid[:3]])
        print(f'\nReconstructed key: {rec}')
        assert rec == tx_key
        log_transaction(user_id, "Reconstruct Key", "Success")
        print('✅ Key reconstruction successful')

        secure_wipe(rec)
secure_wipe(tx_key)
for s in shares:
    secure_wipe(s)
