"""
Tests de integración del protocolo OT.
Requiere que el servidor esté corriendo en localhost:8000.
Ejecutar con: pytest tests/test_protocol.py -v
"""
import os
import time
import pytest
import httpx
from server.crypto import b64_encode, b64_decode, generate_keypair

BASE = "http://localhost:8000"


def init_session() -> dict:
    """Helper: inicia una sesión y devuelve los datos de init."""
    r = httpx.post(f"{BASE}/ot/init", json={})
    assert r.status_code == 200
    return r.json()


# ─── Tests de flujo normal ───────────────────────────────────────────────────

def test_catalog_returns_metadata_only():
    """El catálogo no debe devolver contenido de los ítems."""
    r = httpx.get(f"{BASE}/catalog")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert data["n"] >= 4
    for item in data["items"]:
        assert "id" in item
        assert "name" in item
        assert "size_bytes" in item
        assert "content" not in item


def test_init_returns_valid_session():
    data = init_session()
    assert "session_id" in data
    assert "pk_server" in data
    assert len(b64_decode(data["pk_server"])) == 32
    assert data["n"] >= 4


def test_full_protocol_index_0():
    """Flujo completo para índice 0."""
    _run_full_protocol(0)


def test_full_protocol_index_2():
    """Flujo completo para índice 2."""
    _run_full_protocol(2)


def _run_full_protocol(u: int) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from server.crypto import dh_exchange, derive_blind_key, derive_enc_mac_keys, aes_gcm_decrypt

    init = init_session()
    session_id = init["session_id"]
    pk_server_bytes = b64_decode(init["pk_server"])

    sk = X25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    r = httpx.post(f"{BASE}/ot/transfer", json={
        "session_id": session_id,
        "pk_client": b64_encode(pk_bytes),
        "nonce_transfer": b64_encode(os.urandom(12)),
    })
    assert r.status_code == 200
    ciphertexts = r.json()["ciphertexts"]

    peer_pk = X25519PublicKey.from_public_bytes(pk_server_bytes)
    shared = sk.exchange(peer_pk)
    blind_key = derive_blind_key(shared, session_id, u)
    enc_key, _ = derive_enc_mac_keys(blind_key, session_id, u)

    ct = next(c for c in ciphertexts if c["index"] == u)
    plaintext = aes_gcm_decrypt(enc_key, b64_decode(ct["nonce"]), b64_decode(ct["ct"]))
    assert len(plaintext) > 0

    httpx.post(f"{BASE}/ot/finalize", json={"session_id": session_id})
    return plaintext


# ─── Tests de casos inválidos ────────────────────────────────────────────────

def test_reject_expired_session():
    """Una sesión que no existe debe devolver 410."""
    r = httpx.post(f"{BASE}/ot/transfer", json={
        "session_id": "sesion-inexistente-uuid",
        "pk_client": b64_encode(os.urandom(32)),
        "nonce_transfer": b64_encode(os.urandom(12)),
    })
    assert r.status_code == 410


def test_reject_replay_nonce():
    """Reutilizar el mismo nonce debe devolver 409."""
    init = init_session()
    session_id = init["session_id"]
    _, pk_bytes = generate_keypair()
    nonce = b64_encode(os.urandom(12))

    payload = {
        "session_id": session_id,
        "pk_client": b64_encode(pk_bytes),
        "nonce_transfer": nonce,
    }

    r1 = httpx.post(f"{BASE}/ot/transfer", json=payload)
    assert r1.status_code == 200

    r2 = httpx.post(f"{BASE}/ot/transfer", json=payload)
    assert r2.status_code == 409


def test_reject_malformed_pk_client():
    """Una pk_client de longitud incorrecta debe devolver 400."""
    init = init_session()
    r = httpx.post(f"{BASE}/ot/transfer", json={
        "session_id": init["session_id"],
        "pk_client": b64_encode(os.urandom(16)),
        "nonce_transfer": b64_encode(os.urandom(12)),
    })
    assert r.status_code == 400


def test_client_cannot_decrypt_other_indices():
    """El cliente solo puede descifrar el ítem u; los demás deben fallar."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from server.crypto import dh_exchange, derive_blind_key, derive_enc_mac_keys, aes_gcm_decrypt

    u = 1
    init = init_session()
    session_id = init["session_id"]
    pk_server_bytes = b64_decode(init["pk_server"])

    sk = X25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    r = httpx.post(f"{BASE}/ot/transfer", json={
        "session_id": session_id,
        "pk_client": b64_encode(pk_bytes),
        "nonce_transfer": b64_encode(os.urandom(12)),
    })
    ciphertexts = r.json()["ciphertexts"]

    peer_pk = X25519PublicKey.from_public_bytes(pk_server_bytes)
    shared = sk.exchange(peer_pk)

    for ct_entry in ciphertexts:
        i = ct_entry["index"]
        if i == u:
            continue
        blind_key = derive_blind_key(shared, session_id, u)
        enc_key, _ = derive_enc_mac_keys(blind_key, session_id, u)
        with pytest.raises(Exception):
            aes_gcm_decrypt(enc_key, b64_decode(ct_entry["nonce"]), b64_decode(ct_entry["ct"]))


# ─── Métricas de desempeño ───────────────────────────────────────────────────

def test_measure_transfer_time_and_size():
    """Mide tiempo de /ot/transfer y tamaño de payload para N=4."""
    _, pk_bytes = generate_keypair()
    init = init_session()
    session_id = init["session_id"]

    payload = {
        "session_id": session_id,
        "pk_client": b64_encode(pk_bytes),
        "nonce_transfer": b64_encode(os.urandom(12)),
    }

    t0 = time.perf_counter()
    r = httpx.post(f"{BASE}/ot/transfer", json=payload, timeout=30)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert r.status_code == 200
    payload_size = len(r.content)

    print(f"\n  /ot/transfer — N=4")
    print(f"  Tiempo:         {elapsed_ms:.1f} ms")
    print(f"  Payload (resp): {payload_size} bytes")
    print(f"  Por ítem:       {payload_size // 4} bytes aprox.")

    httpx.post(f"{BASE}/ot/finalize", json={"session_id": session_id})
