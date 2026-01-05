#!/usr/bin/env python3
import uuid
import hashlib
import base64
import secrets
import json
import gi
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

gi.require_version('Secret', '1')

from gi.repository import Secret


ORIGIN = "https://account.jagex.com"
REDIRECT = "https://secure.runescape.com/m=weblogin/launcher-redirect"
CLIENT_ID = "com_jagex_auth_desktop_launcher"

SECRET_SCHEMA = Secret.Schema.new(
    "me.breakgim.runa",
    Secret.SchemaFlags.NONE,
    {
        "session_name": Secret.SchemaAttributeType.STRING,
    }
)


def _pkce_verifier(length: int = 43) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def build_auth_url() -> tuple[str, dict]:
    state = str(uuid.uuid4())
    verifier = _pkce_verifier(43)
    challenge = _pkce_challenge(verifier)

    auth_path = "/oauth2/auth"
    base = urljoin(ORIGIN, auth_path)
    query = urlencode([
        ("flow", "launcher"),
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("prompt", "login"),
        ("scope", "openid offline gamesso.token.create user.profile.read"),
        ("state", state),
    ])
    return f"{base}?{query}", {"state": state, "verifier": verifier}


def build_consent_url(id_token: str) -> tuple[str, str]:
    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    
    consent_path = "/oauth2/auth"
    base = urljoin(ORIGIN, consent_path)
    query = urlencode([
        ("id_token_hint", id_token),
        ("nonce", nonce),
        ("prompt", "consent"),
        ("response_type", "id_token code"),
        ("client_id", "1fddee4e-b100-4f4e-b2b0-097f9088f9d2"),
        ("redirect_uri", "http://localhost"),
        ("scope", "openid offline"),
        ("state", state),
    ])
    return f"{base}?{query}", state


def exchange_token(code: str, verifier: str) -> str:
    url = "https://account.jagex.com/oauth2/token"
    data = urlencode({
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT,
    }).encode('utf-8')
    
    request = Request(url, data=data, method='POST')
    with urlopen(request) as response:
        tokens = json.loads(response.read().decode('utf-8'))
        return tokens['id_token']


def create_session(id_token: str) -> str:
    url = "https://auth.jagex.com/game-session/v1/sessions"
    body = json.dumps({"idToken": id_token}).encode('utf-8')
    
    request = Request(url, data=body, method='POST')
    request.add_header('Content-Type', 'application/json')
    request.add_header('Accept', 'application/json')
    
    with urlopen(request) as response:
        result = json.loads(response.read().decode('utf-8'))
        return result.get('sessionId')


def fetch_accounts(session_id: str) -> list:
    url = "https://auth.jagex.com/game-session/v1/accounts"
    
    request = Request(url, method='GET')
    request.add_header('Content-Type', 'application/json')
    request.add_header('Accept', 'application/json')
    request.add_header('Authorization', f'Bearer {session_id}')
    
    with urlopen(request) as response:
        return json.loads(response.read().decode('utf-8'))


class SessionManager:
    
    @staticmethod
    def store_session(session_id: str):
        data = json.dumps({"session_id": session_id})
        Secret.password_store_sync(
            SECRET_SCHEMA,
            {"session_name": "default"},
            Secret.COLLECTION_DEFAULT,
            "Runa Session",
            data,
            None
        )

    @staticmethod
    def load_session() -> dict:
        password = Secret.password_lookup_sync(
            SECRET_SCHEMA,
            {"session_name": "default"},
            None
        )
        if password:
            return json.loads(password)
        return None
    
    @staticmethod
    def clear_session():
        Secret.password_clear_sync(
            SECRET_SCHEMA,
            {"session_name": "default"},
            None
        )
