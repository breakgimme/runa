#!/usr/bin/env python3
import sys
import gi
import threading
import os
import subprocess
import time
import traceback
import uuid
import hashlib
import base64
import secrets
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('WebKit', '6.0')
gi.require_version('Secret', '1')

from gi.repository import Gtk, Adw, WebKit, GLib, Gio, Secret


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
    request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36')
    with urlopen(request) as response:
        tokens = json.loads(response.read().decode('utf-8'))
        return tokens['id_token']


def create_session(id_token: str) -> str:
    url = "https://auth.jagex.com/game-session/v1/sessions"
    body = json.dumps({"idToken": id_token}).encode('utf-8')

    request = Request(url, data=body, method='POST')
    request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36')
    request.add_header('Content-Type', 'application/json')
    request.add_header('Accept', 'application/json')

    with urlopen(request) as response:
        result = json.loads(response.read().decode('utf-8'))
        return result.get('sessionId')


def fetch_accounts(session_id: str) -> list:
    url = "https://auth.jagex.com/game-session/v1/accounts"

    request = Request(url, method='GET')
    request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36')
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


GAME_CLIENTS = {
    "RuneLite": {
        "url": "https://github.com/runelite/launcher/releases/download/2.7.7/RuneLite.jar",
        "filename": "RuneLite.jar"
    },
    "HDOS": {
        "url": "https://cdn.hdos.dev/launcher/latest/hdos-launcher.jar",
        "filename": "hdos-launcher.jar"
    }
}


def get_clients_dir():
    data_dir = Path.home() / ".local" / "share" / "runa" / "clients"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


class ClientManager:
    @staticmethod
    def is_downloaded(client_name: str) -> bool:
        client_info = GAME_CLIENTS.get(client_name)
        if not client_info:
            return False
        client_path = get_clients_dir() / client_info["filename"]
        return client_path.exists()
    
    @staticmethod
    def download_client(client_name: str, progress_callback=None):
        client_info = GAME_CLIENTS.get(client_name)
        if not client_info:
            raise ValueError(f"Unknown client: {client_name}")
        
        client_path = get_clients_dir() / client_info["filename"]
        url = client_info["url"]
        
        request = Request(url)
        with urlopen(request) as response:
            total_size = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            
            with open(client_path, 'wb') as f:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total_size > 0:
                        progress = downloaded / total_size
                        GLib.idle_add(progress_callback, progress)
        
        return client_path
    
    @staticmethod
    def delete_client(client_name: str):
        client_info = GAME_CLIENTS.get(client_name)
        if not client_info:
            return
        
        client_path = get_clients_dir() / client_info["filename"]
        if client_path.exists():
            client_path.unlink()
    
    @staticmethod
    def launch_client(client_name: str, session_id: str, character_id: str, display_name: str, java_path: str = "java"):
        client_info = GAME_CLIENTS.get(client_name)
        if not client_info:
            raise ValueError(f"Unknown client: {client_name}")
        
        client_path = get_clients_dir() / client_info["filename"]
        if not client_path.exists():
            raise FileNotFoundError(f"{client_name} is not downloaded")
        
        env = os.environ.copy()
        env["JX_SESSION_ID"] = session_id
        env["JX_CHARACTER_ID"] = character_id
        env["JX_DISPLAY_NAME"] = display_name
        
        try:
            process = subprocess.Popen(
                [java_path, "-jar", str(client_path)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            poll = process.poll()
            if poll is not None and poll != 0:
                stderr = process.stderr.read().decode('utf-8', errors='ignore').strip()
                if stderr:
                    raise RuntimeError(stderr)
                else:
                    raise RuntimeError(f"Failed to launch {client_name}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Java binary not found at: {java_path}")
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"Failed to launch {client_name}: {str(e)}")



class MainWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("Runa")
        self.set_default_size(500, 700)
        
        self._pkce = None
        self._consent_state = None
        self._id_token = None
        self._session_id = None
        self._validating_session = False
        self._accounts = []
        self._client_names = list(GAME_CLIENTS.keys())
        self._settings = Gio.Settings.new("me.breakgim.runa")

        self._load_ui()
        self._setup_actions()
        self._setup_webview()
        self._populate_client_dropdown()
        self._load_settings()

        self.stack.set_visible_child_name("login")
        self.set_content(self.toolbar_view)

        self.check_existing_session()

    def _get_ui_object(self, object_id):
        widget = self.builder.get_object(object_id)
        if widget is None:
            raise RuntimeError(f"Missing UI object: {object_id}")
        return widget

    def _load_ui(self):
        self.builder = Gtk.Builder.new_from_file(str(Path(__file__).with_name("main.ui")))
        self.toolbar_view = self._get_ui_object("toolbar_view")
        self.header_bar = self._get_ui_object("header_bar")
        self.back_button = self._get_ui_object("back_button")
        self.menu_button = self._get_ui_object("menu_button")
        self.stack = self._get_ui_object("stack")
        self.login_btn = self._get_ui_object("login_btn")
        self.character_dropdown = self._get_ui_object("character_dropdown")
        self.client_dropdown = self._get_ui_object("client_dropdown")
        self.delete_btn = self._get_ui_object("delete_btn")
        self.play_btn = self._get_ui_object("play_btn")
        self.play_label = self._get_ui_object("play_label")
        self.close_after_launch_row = self._get_ui_object("close_after_launch_row")
        self.java_path_row = self._get_ui_object("java_path_row")

        self.back_button.connect("clicked", self.on_settings_back_clicked)
        self.login_btn.connect("clicked", self.on_login_clicked)
        self.client_dropdown.connect("notify::selected", self.on_client_changed)
        self.delete_btn.connect("clicked", self.on_delete_client_clicked)
        self.play_btn.connect("clicked", self.on_play_clicked)
        self.close_after_launch_row.connect("notify::active", self.on_close_after_launch_changed)
        self.java_path_row.connect("apply", self.on_java_path_changed)
        self.java_path_row.connect("entry-activated", self.on_java_path_changed)

    def _setup_actions(self):
        menu = Gio.Menu()

        settings_action = Gio.SimpleAction.new("settings", None)
        settings_action.connect("activate", self.on_settings_clicked)
        self.add_action(settings_action)
        menu.append("Settings", "win.settings")

        self.sign_out_action = Gio.SimpleAction.new("sign-out", None)
        self.sign_out_action.connect("activate", self.on_sign_out_clicked)
        self.sign_out_action.set_enabled(False)
        self.add_action(self.sign_out_action)
        menu.append("Sign out", "win.sign-out")

        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self.on_about_clicked)
        self.add_action(about_action)
        menu.append("About", "win.about")

        self.menu_button.set_menu_model(menu)

    def _setup_webview(self):
        data_dir = Path(GLib.get_user_data_dir()) / "runa" / "webkit"
        cache_dir = data_dir / "cache"
        data_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.mkdir(parents=True, exist_ok=True)

        network_session = WebKit.NetworkSession(
            data_directory=str(data_dir),
            cache_directory=str(cache_dir),
        )

        self.webview = WebKit.WebView(network_session=network_session)
        self.webview.set_hexpand(True)
        self.webview.set_vexpand(True)
        self.webview.connect("decide-policy", self.on_navigation)

        user_content_manager = self.webview.get_user_content_manager()
        cookiebot_css = "#CybotCookiebotDialog, #CybotCookiebotDialogBodyUnderlay { display: none !important; }"
        user_style_sheet = WebKit.UserStyleSheet.new(
            cookiebot_css,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserStyleLevel.USER,
            None,
            None,
        )
        user_content_manager.add_style_sheet(user_style_sheet)
        self.stack.add_named(self.webview, "webview")

    def _populate_client_dropdown(self):
        client_string_list = Gtk.StringList()
        for client_name in self._client_names:
            client_string_list.append(client_name)

        self.client_dropdown.set_model(client_string_list)

        last_client = self._settings.get_string("last-client")
        if last_client in self._client_names:
            self.client_dropdown.set_selected(self._client_names.index(last_client))
        else:
            self.client_dropdown.set_selected(0)

    def _load_settings(self):
        self.close_after_launch_row.set_active(self._settings.get_boolean("close-after-launch"))

        java_path = self._settings.get_string("java-path")
        self.java_path_row.set_text(java_path if java_path else "java")
    
    def check_existing_session(self):
        session_data = SessionManager.load_session()
        if session_data and "session_id" in session_data:
            self._session_id = session_data["session_id"]
            self._validating_session = True
            GLib.idle_add(self.login_btn.set_sensitive, False)
            threading.Thread(target=self.validate_and_load_session, daemon=True).start()
    
    def validate_and_load_session(self):
        try:
            accounts = fetch_accounts(self._session_id)
            if accounts:
                self._accounts = accounts
                GLib.idle_add(self.show_character_selection)
        except HTTPError as e:
            if getattr(e, "code", None) in (401, 403):
                SessionManager.clear_session()
                self._session_id = None
            GLib.idle_add(lambda: self.stack.set_visible_child_name("login"))
        except URLError:
            GLib.idle_add(lambda: self.stack.set_visible_child_name("login"))
        except Exception:
            GLib.idle_add(lambda: self.stack.set_visible_child_name("login"))
        finally:
            self._validating_session = False
            if self._session_id is None:
                GLib.idle_add(self.login_btn.set_sensitive, True)
            else:
                GLib.idle_add(self.login_btn.set_sensitive, False)
    
    def on_navigation(self, webview, decision, decision_type):
        if decision_type != WebKit.PolicyDecisionType.NAVIGATION_ACTION:
            return False
        
        nav_action = decision.get_navigation_action()
        request = nav_action.get_request()
        uri = request.get_uri()
        
        if uri.startswith(REDIRECT):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            
            if 'code' in query and 'state' in query:
                code = query['code'][0]
                state = query['state'][0]
                
                if state != self._pkce['state']:
                    decision.ignore()
                    return True

                def continue_to_consent():
                    try:
                        self._id_token = exchange_token(code, self._pkce['verifier'])

                        consent_url, consent_state = build_consent_url(self._id_token)
                        self._consent_state = consent_state

                        GLib.idle_add(lambda: self.webview.load_uri(consent_url))
                    except Exception:
                        traceback.print_exc()

                threading.Thread(target=continue_to_consent, daemon=True).start()
                decision.ignore()
                return True
        
        if uri.startswith("http://localhost"):
            if '#' in uri:
                fragment_part = uri.split('#')[1]
                fragment_query = parse_qs(fragment_part)
                
                if 'id_token' in fragment_query and 'state' in fragment_query:
                    id_token = fragment_query['id_token'][0]
                    state = fragment_query['state'][0]
                    
                    if state != self._consent_state:
                        decision.ignore()
                        return True

                    def complete_login():
                        try:
                            self._session_id = create_session(id_token)
                            SessionManager.store_session(self._session_id)

                            self._accounts = fetch_accounts(self._session_id)
                            GLib.idle_add(self.show_character_selection)
                        except Exception:
                            traceback.print_exc()

                    threading.Thread(target=complete_login, daemon=True).start()
                    decision.ignore()
                    return True
        
        return False
    
    def show_character_selection(self):
        self.back_button.set_visible(False)
        self.sign_out_action.set_enabled(True)

        string_list = Gtk.StringList()
        for account in self._accounts:
            display = account.get('displayName') or account['accountId']
            string_list.append(display)

        self.character_dropdown.set_model(string_list)
        self.character_dropdown.set_selected(0)

        last_client = self._settings.get_string("last-client")
        if last_client in self._client_names:
            self.client_dropdown.set_selected(self._client_names.index(last_client))
        else:
            self.client_dropdown.set_selected(0)

        self.update_delete_button_visibility()
        self.stack.set_visible_child_name("characters")
    
    def on_client_changed(self, dropdown, param):
        selected_idx = dropdown.get_selected()
        if 0 <= selected_idx < len(self._client_names):
            client_name = self._client_names[selected_idx]
            if hasattr(self, "delete_btn"):
                self._update_delete_button(client_name)
            self._settings.set_string("last-client", client_name)
        return False

    def _update_delete_button(self, client_name):
        is_downloaded = ClientManager.is_downloaded(client_name)
        self.delete_btn.set_visible(is_downloaded)
    
    def update_delete_button_visibility(self):
        selected_idx = self.client_dropdown.get_selected()
        if 0 <= selected_idx < len(self._client_names):
            self._update_delete_button(self._client_names[selected_idx])
    
    def on_delete_client_clicked(self, button):
        selected_idx = self.client_dropdown.get_selected()
        if selected_idx < len(self._client_names):
            client_name = self._client_names[selected_idx]
            
            dialog = Adw.AlertDialog.new(
                f"Delete {client_name}?",
                f"Are you sure you want to delete {client_name}?"
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("delete", "Delete")
            dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            
            def on_response(dialog, response):
                if response == "delete":
                    ClientManager.delete_client(client_name)
                    self.update_delete_button_visibility()
            
            dialog.connect("response", on_response)
            dialog.present(self)
    
    def show_error_dialog(self, title, message):
        dialog = Adw.AlertDialog.new(title, message)
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.present(self)
    
    def on_play_clicked(self, button):
        selected_idx = self.character_dropdown.get_selected()
        if selected_idx >= len(self._accounts):
            return
        
        account = self._accounts[selected_idx]
        account_id = account['accountId']
        display_name = account.get('displayName', '')
        
        client_idx = self.client_dropdown.get_selected()
        if client_idx >= len(self._client_names):
            return
        
        client_name = self._client_names[client_idx]
        
        if not ClientManager.is_downloaded(client_name):
            button.set_sensitive(False)
            self.play_label.set_label("Downloading...")
            threading.Thread(
                target=self._download_and_launch,
                args=(client_name, account_id, display_name, button),
                daemon=True
            ).start()
        else:
            try:
                java_path = self._settings.get_string("java-path")
                if not java_path:
                    java_path = "java"
                ClientManager.launch_client(client_name, self._session_id, account_id, display_name, java_path)
                if self._settings.get_boolean("close-after-launch"):
                    self.close()
            except Exception as e:
                self.show_error_dialog("Launch Failed", str(e))
    
    def _download_and_launch(self, client_name, account_id, display_name, button):
        try:
            ClientManager.download_client(client_name)
            GLib.idle_add(self.update_delete_button_visibility)
            java_path = self._settings.get_string("java-path")
            if not java_path:
                java_path = "java"
            ClientManager.launch_client(client_name, self._session_id, account_id, display_name, java_path)
            if self._settings.get_boolean("close-after-launch"):
                GLib.idle_add(self.close)
        except Exception as e:
            GLib.idle_add(self.show_error_dialog, "Launch Failed", str(e))
        finally:
            GLib.idle_add(button.set_sensitive, True)
            GLib.idle_add(self.play_label.set_label, "Launch")
    
    def on_sign_out_clicked(self, action, param):
        SessionManager.clear_session()
        self._session_id = None
        self._accounts = []
        self.sign_out_action.set_enabled(False)
        self.stack.set_visible_child_name("login")
        self.login_btn.set_sensitive(True)
    
    def on_settings_clicked(self, action, param):
        self.show_settings_page()

    def on_about_clicked(self, action, param):
        dialog = Adw.AboutDialog()
        dialog.set_application_name("Runa")
        dialog.set_application_icon("me.breakgim.runa")
        dialog.set_developer_name("breakgimme")
        dialog.set_version(self.get_application().version)
        dialog.set_website("https://github.com/breakgimme/runa")
        dialog.present(self)
    
    def show_settings_page(self):
        self.back_button.set_visible(True)

        self.close_after_launch_row.set_active(self._settings.get_boolean("close-after-launch"))
        java_path = self._settings.get_string("java-path")
        self.java_path_row.set_text(java_path if java_path else "java")
        self.stack.set_visible_child_name("settings")
    
    def on_close_after_launch_changed(self, switch_row, param):
        self._settings.set_boolean("close-after-launch", switch_row.get_active())
    
    def on_java_path_changed(self, entry_row, *args):
        java_path = entry_row.get_text().strip()
        if java_path:
            self._settings.set_string("java-path", java_path)
        else:
            self._settings.set_string("java-path", "java")
    
    def on_settings_back_clicked(self, button):
        self.back_button.set_visible(False)
        current_view = self.stack.get_visible_child_name()
        
        if current_view == "webview":
            self.webview.stop_loading()
            self.webview.load_uri("about:blank")
            self.stack.set_visible_child_name("login")
        elif self._session_id and self.stack.get_child_by_name("characters"):
            self.stack.set_visible_child_name("characters")
        else:
            self.stack.set_visible_child_name("login")
    
    def on_login_clicked(self, button):
        if self._validating_session:
            return
        url, pkce = build_auth_url()
        self._pkce = pkce
        self.back_button.set_visible(True)
        self.stack.set_visible_child_name("webview")
        GLib.idle_add(lambda: self.webview.load_uri(url))


class MyApp(Adw.Application):
    def __init__(self, version=None, **kwargs):
        super().__init__(**kwargs)
        self.version = version
        self.connect('activate', self.on_activate)
    
    def on_activate(self, app):
        win = MainWindow(application=app)
        win.present()


def main(version=None):
    app = MyApp(application_id='me.breakgim.runa', version=version)
    return app.run(sys.argv)
