"""Primitivas criptográficas compartidas por servidor y cliente."""
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
import base64


def generate_keypair() -> tuple[X25519PrivateKey, bytes]:
    sk = X25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk_bytes


def dh_exchange(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_pk = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_pk)


def derive_blind_key(shared_secret: bytes, session_id: str, index: int) -> bytes:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=f"blind|{session_id}|{index}".encode(),
    )
    return hkdf.derive(shared_secret)


def derive_enc_mac_keys(blind_key: bytes, session_id: str, index: int) -> tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=64,
        salt=None,
        info=f"enc|{session_id}|{index}".encode(),
    )
    key_material = hkdf.derive(blind_key)
    return key_material[:32], key_material[32:]


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def b64_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode())
