"""
CLI del cliente OT.

Uso:
    python client/cli.py list  --server http://localhost:8000
    python client/cli.py get   --server http://localhost:8000 --index 2 --out item.bin
"""
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import httpx
import typer
from cryptography.exceptions import InvalidTag
from rich.console import Console
from rich.table import Table

from client.crypto import client_run_ot
from server.crypto import b64_encode

app = typer.Typer(help="Cliente OT 1-de-N — descarga privada de ítems")
console = Console()


@app.command()
def list(
    server: str = typer.Option("http://localhost:8000", help="URL base del servidor"),
):
    """Muestra el catálogo de ítems disponibles (sin revelar contenido)."""
    try:
        response = httpx.get(f"{server}/catalog", timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        console.print(f"[red]Error al conectar con el servidor:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(title=f"Catálogo — {data['n']} ítems disponibles")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Nombre", style="white")
    table.add_column("Tamaño (bytes)", justify="right")
    table.add_column("Descripción")

    for item in data["items"]:
        table.add_row(
            str(item["id"]),
            item["name"],
            str(item["size_bytes"]),
            item.get("description", ""),
        )

    console.print(table)


@app.command()
def get(
    server: str = typer.Option("http://localhost:8000", help="URL base del servidor"),
    index: int = typer.Option(..., "--index", "-i", help="Índice u del ítem a descargar"),
    out: str = typer.Option(..., "--out", "-o", help="Archivo de salida"),
):
    """
    Descarga privada del ítem en posición --index.
    El servidor no aprende qué índice se eligió.
    """
    console.print(f"[bold]Iniciando OT para índice u={index}[/bold]")

    try:
        response = httpx.post(
            f"{server}/ot/init",
            json={"client_version": "1.0.0"},
            timeout=10,
        )
        response.raise_for_status()
        init_data = response.json()
    except Exception as exc:
        console.print(f"[red]Error en /ot/init:[/red] {exc}")
        raise typer.Exit(1)

    session_id = init_data["session_id"]
    pk_server = init_data["pk_server"]
    n = init_data["n"]

    if index < 0 or index >= n:
        console.print(f"[red]Índice {index} fuera de rango [0, {n - 1}][/red]")
        raise typer.Exit(1)

    console.print(f"  Sesión: {session_id[:16]}...  N={n}")

    sk_client = None
    pk_client_bytes = None

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        sk_client = X25519PrivateKey.generate()
        pk_client_bytes = sk_client.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        nonce_transfer = b64_encode(os.urandom(12))

        response = httpx.post(
            f"{server}/ot/transfer",
            json={
                "session_id": session_id,
                "pk_client": b64_encode(pk_client_bytes),
                "nonce_transfer": nonce_transfer,
            },
            timeout=30,
        )
        response.raise_for_status()
        transfer_data = response.json()
    except Exception as exc:
        console.print(f"[red]Error en /ot/transfer:[/red] {exc}")
        raise typer.Exit(1)

    ciphertexts = transfer_data["ciphertexts"]
    console.print(f"  Recibidos {len(ciphertexts)} ciphertexts del servidor")

    try:
        plaintext, _ = client_run_ot(
            pk_server_b64=pk_server,
            session_id=session_id,
            index_u=index,
            ciphertexts=ciphertexts,
            sk_client=sk_client,
            pk_client_bytes=pk_client_bytes,
        )
    except (ValueError, InvalidTag) as exc:
        console.print(f"[red]Error de descifrado:[/red] {exc}")
        raise typer.Exit(1)

    try:
        httpx.post(
            f"{server}/ot/finalize",
            json={"session_id": session_id},
            timeout=10,
        )
    except Exception:
        pass

    pathlib.Path(out).write_bytes(plaintext)
    console.print(f"[green]✓ Ítem {index} descargado → {out} ({len(plaintext)} bytes)[/green]")
    console.print("[dim]El servidor no registró qué índice se descargó.[/dim]")


if __name__ == "__main__":
    app()