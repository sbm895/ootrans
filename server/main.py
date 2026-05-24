"""
Servidor OT 1-de-N sobre X25519 / HKDF / AES-GCM.
Expone: GET /catalog, POST /ot/init, POST /ot/transfer, POST /ot/finalize
"""
import os
import uuid
import time
import pathlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

from server.sessions import store
from server.crypto import (
    generate_keypair, dh_exchange,
    derive_blind_key, derive_enc_mac_keys,
    aes_gcm_encrypt, b64_encode, b64_decode
)

app = FastAPI(title="OT 1-de-N Server", version="1.0.0")

DATA_DIR = pathlib.Path(__file__).parent.parent / "data"


class InitRequest(BaseModel):
    client_version: Optional[str] = "1.0.0"


class TransferRequest(BaseModel):
    session_id: str
    pk_client: str
    nonce_transfer: str


class FinalizeRequest(BaseModel):
    session_id: str


def load_catalog() -> list[dict]:
    items = []
    for i, path in enumerate(sorted(DATA_DIR.glob("*"))):
        if path.is_file():
            items.append({
                "id": i,
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "description": f"Ítem confidencial #{i}",
            })
    return items


def load_item_bytes(index: int) -> bytes:
    paths = sorted(p for p in DATA_DIR.glob("*") if p.is_file())
    if index < 0 or index >= len(paths):
        raise ValueError(f"Índice {index} fuera de rango")
    return paths[index].read_bytes()


@app.get("/catalog")
def get_catalog():
    items = load_catalog()
    return {
        "items": items,
        "n": len(items),
        "server_version": "1.0.0",
    }


@app.post("/ot/init")
def ot_init(body: InitRequest):
    sk, pk_bytes = generate_keypair()
    session_id = str(uuid.uuid4())
    nonce_init = b64_encode(os.urandom(12))
    store.create(session_id, sk, pk_bytes, nonce_init)
    return {
        "session_id": session_id,
        "pk_server": b64_encode(pk_bytes),
        "n": len(load_catalog()),
        "nonce_init": nonce_init,
        "expires_at": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() + 300)
        ),
        "algo": "X25519-HKDF-SHA256-AES256GCM",
    }


@app.post("/ot/transfer")
def ot_transfer(body: TransferRequest):
    session = store.get(body.session_id)
    if session is None or not session.is_valid():
        raise HTTPException(status_code=410, detail="Sesión inválida o expirada")

    if not store.register_nonce(body.session_id, body.nonce_transfer):
        raise HTTPException(status_code=409, detail="Nonce duplicado (posible replay)")

    try:
        pk_client_bytes = b64_decode(body.pk_client)
        if len(pk_client_bytes) != 32:
            raise ValueError("Longitud incorrecta")
    except Exception:
        raise HTTPException(status_code=400, detail="pk_client malformada")

    try:
        shared = dh_exchange(session.private_key, pk_client_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="pk_client fuera de la curva")

    items = load_catalog()
    ciphertexts = []

    for i in range(len(items)):
        xi = load_item_bytes(i)
        blind_key = derive_blind_key(shared, body.session_id, i)
        enc_key, _ = derive_enc_mac_keys(blind_key, body.session_id, i)
        nonce, ct = aes_gcm_encrypt(enc_key, xi)
        ciphertexts.append({
            "index": i,
            "nonce": b64_encode(nonce),
            "ct": b64_encode(ct),
        })

    return {
        "session_id": body.session_id,
        "ciphertexts": ciphertexts,
    }


@app.post("/ot/finalize")
def ot_finalize(body: FinalizeRequest):
    session = store.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=410, detail="Sesión no encontrada")

    store.close(body.session_id)
    return {"status": "closed", "session_id": body.session_id}
