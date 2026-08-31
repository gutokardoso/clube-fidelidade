import base64
import hashlib
import hmac
import os
import secrets
import time

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ROUNDS = 600_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS)
    return f'pbkdf2_sha256${PBKDF2_ROUNDS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}'


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_b64, digest_b64 = encoded.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(rounds))
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def now_ts() -> int:
    return int(time.time())



def password_is_strong(password: str, min_length: int = 12) -> bool:
    """Política para senhas novas. Hashes antigos continuam válidos no login."""
    if not isinstance(password, str) or len(password) < min_length:
        return False
    return (
        any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    )


def generate_totp_secret() -> str:
    # 160 bits, padrão compatível com Google/Microsoft Authenticator e 1Password.
    return base64.b32encode(os.urandom(20)).decode('ascii').rstrip('=')


def _totp_at(secret: str, counter: int, digits: int = 6) -> str:
    padded = secret.upper() + '=' * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = int(counter).to_bytes(8, 'big')
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = ((digest[off] & 0x7F) << 24) | (digest[off+1] << 16) | (digest[off+2] << 8) | digest[off+3]
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, at_time: int | None = None, window: int = 1) -> bool:
    code = ''.join(c for c in str(code or '') if c.isdigit())
    if len(code) != 6 or not secret:
        return False
    now = int(at_time or time.time())
    counter = now // 30
    for delta in range(-window, window + 1):
        try:
            if hmac.compare_digest(_totp_at(secret, counter + delta), code):
                return True
        except Exception:
            return False
    return False


PII_PREFIX = "enc:v1:"

def _encryption_master():
    return os.environ.get("CLUBE_ENCRYPTION_KEY", "").strip()

def pii_key_configured() -> bool:
    return bool(_encryption_master())

def _pii_box():
    master = _encryption_master()
    if not master:
        return None
    key = base64.urlsafe_b64encode(hashlib.sha256(("fidelizae-pii-v1:" + master).encode("utf-8")).digest())
    return Fernet(key)

def canonicalize_pii(value, purpose: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if purpose in ("cpf", "phone"):
        return "".join(ch for ch in value if ch.isdigit())
    return value

def encrypt_pii(value, purpose: str) -> str | None:
    plain = canonicalize_pii(value, purpose)
    if not plain:
        return None
    box = _pii_box()
    if not box:
        raise RuntimeError("encryption_key_not_configured")
    token = box.encrypt(plain.encode("utf-8")).decode("ascii")
    return PII_PREFIX + token

def decrypt_pii(value, purpose: str) -> str:
    raw = str(value or "")
    if not raw:
        return ""
    # Compatibilidade durante migração: valores antigos em texto puro continuam legíveis.
    if not raw.startswith(PII_PREFIX):
        return canonicalize_pii(raw, purpose)
    box = _pii_box()
    if not box:
        return ""
    try:
        return box.decrypt(raw[len(PII_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""

def pii_lookup_hash(value, purpose: str) -> str | None:
    plain = canonicalize_pii(value, purpose)
    if not plain:
        return None
    master = _encryption_master()
    if not master:
        raise RuntimeError("encryption_key_not_configured")
    key = hashlib.sha256(("fidelizae-pii-index-v1:" + master).encode("utf-8")).digest()
    return hmac.new(key, (purpose + ":" + plain).encode("utf-8"), hashlib.sha256).hexdigest()
