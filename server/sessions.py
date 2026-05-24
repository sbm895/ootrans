"""
Almacén de sesiones en memoria con TTL.
Cada sesión guarda el keypair efímero del servidor y los nonces usados.
"""
import time
import threading
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

SESSION_TTL_SECONDS = 300  # 5 minutos


@dataclass
class Session:
    session_id: str
    private_key: X25519PrivateKey
    public_key_bytes: bytes
    nonce_init: str
    created_at: float = field(default_factory=time.time)
    used_nonces: set = field(default_factory=set)
    closed: bool = False

    def is_expired(self) -> bool:
        return time.time() - self.created_at > SESSION_TTL_SECONDS

    def is_valid(self) -> bool:
        return not self.closed and not self.is_expired()


class SessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._start_cleanup_thread()

    def create(self, session_id: str, private_key, public_key_bytes: bytes, nonce_init: str) -> Session:
        session = Session(
            session_id=session_id,
            private_key=private_key,
            public_key_bytes=public_key_bytes,
            nonce_init=nonce_init,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def close(self, session_id: str):
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.closed = True
                session.private_key = None

    def register_nonce(self, session_id: str, nonce: str) -> bool:
        """Registra un nonce. Devuelve False si ya fue usado (replay)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            if nonce in session.used_nonces:
                return False
            session.used_nonces.add(nonce)
            return True

    def _cleanup(self):
        while True:
            time.sleep(60)
            with self._lock:
                expired = [sid for sid, s in self._sessions.items() if s.is_expired()]
                for sid in expired:
                    del self._sessions[sid]

    def _start_cleanup_thread(self):
        t = threading.Thread(target=self._cleanup, daemon=True)
        t.start()


# Singleton global
store = SessionStore()
