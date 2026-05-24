"""
Lógica criptográfica del lado del cliente para el protocolo OT 1-de-N.
El cliente genera su propio keypair efímero y solo puede descifrar el ítem u.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from cryptography.exceptions import InvalidTag

from server.crypto import (
    aes_gcm_decrypt,
    b64_decode,
    derive_blind_key,
    derive_enc_mac_keys,
    dh_exchange,
    generate_keypair,
)


def client_run_ot(
    pk_server_b64: str,
    session_id: str,
    index_u: int,
    ciphertexts: list[dict],
    sk_client=None,
    pk_client_bytes: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Ejecuta el lado cliente del protocolo OT.

    Parámetros:
        pk_server_b64 : clave pública del servidor (base64url, 32 bytes)
        session_id    : identificador de sesión
        index_u       : índice secreto del ítem deseado
        ciphertexts   : lista de dicts con {index, nonce, ct} del servidor

    Devuelve:
        (bytes del ítem Xu descifrado, pk_client_bytes)

    Lanza:
        ValueError si el índice no existe en los ciphertexts.
        InvalidTag  si el descifrado falla (ítem corrupto o ataque).
    """
    pk_server_bytes = b64_decode(pk_server_b64)

    if sk_client is None or pk_client_bytes is None:
        sk_client, pk_client_bytes = generate_keypair()
    shared = dh_exchange(sk_client, pk_server_bytes)

    blind_key_u = derive_blind_key(shared, session_id, index_u)
    enc_key_u, _ = derive_enc_mac_keys(blind_key_u, session_id, index_u)

    ct_entry = next((c for c in ciphertexts if c["index"] == index_u), None)
    if ct_entry is None:
        raise ValueError(f"El servidor no devolvió ciphertext para índice {index_u}")

    nonce = b64_decode(ct_entry["nonce"])
    ct = b64_decode(ct_entry["ct"])

    plaintext = aes_gcm_decrypt(enc_key_u, nonce, ct)
    return plaintext, pk_client_bytes