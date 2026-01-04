#!/usr/bin/env python3
import sys
import gi
import uuid
import hashlib
import base64
import secrets
import json
import threading
import os
import subprocess
import time
import traceback
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('WebKit', '6.0')
gi.require_version('Secret', '1')

from gi.repository import Gtk, Adw, WebKit, GLib, Secret, Gio


ORIGIN = "https://account.jagex.com"
REDIRECT = "https://secure.runescape.com/m=weblogin/launcher-redirect"
CLIENT_ID = "com_jagex_auth_desktop_launcher"

GAME_CLIENTS = {
    "RuneLite": {
        "url": "https://github.com/runelite/launcher/releases/download/2.7.6/RuneLite.jar",
        "filename": "RuneLite.jar"
    },
    "HDOS": {
        "url": "https://cdn.hdos.dev/launcher/latest/hdos-launcher.jar",
        "filename": "hdos-launcher.jar"
    }
}

SECRET_SCHEMA = Secret.Schema.new(
    "me.breakgim.runa",
    Secret.SchemaFlags.NONE,
    {
        "session_name": Secret.SchemaAttributeType.STRING,
    }
)


def get_clients_dir():
    data_dir = Path.home() / ".local" / "share" / "runa" / "clients"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


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
        
        self.header_bar = Adw.HeaderBar()
        
        self.back_button = Gtk.Button(icon_name="go-previous-symbolic")
        self.back_button.connect("clicked", self.on_settings_back_clicked)
        self.back_button.set_visible(False)
        self.header_bar.pack_start(self.back_button)
        
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        
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
        
        menu_button.set_menu_model(menu)
        self.header_bar.pack_end(menu_button)
        
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        
        self.create_login_view()

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

        
        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(self.header_bar)
        toolbar_view.set_content(self.stack)
        
        self.set_content(toolbar_view)
        
        self.check_existing_session()
    
    def create_login_view(self):
        login_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        login_box.set_halign(Gtk.Align.CENTER)
        login_box.set_valign(Gtk.Align.CENTER)
        login_box.set_margin_top(40)
        login_box.set_margin_bottom(40)
        login_box.set_margin_start(40)
        login_box.set_margin_end(40)
        
        title = Gtk.Label(label="Runa")
        title.add_css_class("title-1")
        login_box.append(title)
        
        self.login_btn = Gtk.Button(label="Login")
        self.login_btn.add_css_class("suggested-action")
        self.login_btn.add_css_class("pill")
        self.login_btn.set_size_request(200, 50)
        self.login_btn.connect("clicked", self.on_login_clicked)
        login_box.append(self.login_btn)
        
        self.stack.add_named(login_box, "login")
        self.stack.set_visible_child_name("login")
    
    def check_existing_session(self):
        session_data = SessionManager.load_session()
        if session_data and "session_id" in session_data:
            self._session_id = session_data["session_id"]
            self._validating_session = True
            GLib.idle_add(self.login_btn.set_sensitive, False)
            threading.Thread(target=self.validate_and_load_session, daemon=True).start()
    
    def validate_and_load_session(self):
        try:
            accounts = self.fetch_accounts_sync()
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
                
                threading.Thread(target=self.exchange_token, args=(code,), daemon=True).start()
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
                    
                    threading.Thread(target=self.create_session, args=(id_token,), daemon=True).start()
                    decision.ignore()
                    return True
        
        return False
    
    def exchange_token(self, code):
        url = "https://account.jagex.com/oauth2/token"
        data = urlencode({
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "code_verifier": self._pkce['verifier'],
            "redirect_uri": REDIRECT,
        }).encode('utf-8')
        
        try:
            request = Request(url, data=data, method='POST')
            with urlopen(request) as response:
                tokens = json.loads(response.read().decode('utf-8'))
                self._id_token = tokens['id_token']
                
                consent_url, consent_state = self.build_consent_url(self._id_token)
                self._consent_state = consent_state
                
                GLib.idle_add(lambda: self.webview.load_uri(consent_url))
        except Exception as e:
            traceback.print_exc()
    
    def build_consent_url(self, id_token):
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
    
    def create_session(self, id_token):
        url = "https://auth.jagex.com/game-session/v1/sessions"
        body = json.dumps({"idToken": id_token}).encode('utf-8')
        
        try:
            request = Request(url, data=body, method='POST')
            request.add_header('Content-Type', 'application/json')
            request.add_header('Accept', 'application/json')
            
            with urlopen(request) as response:
                result = json.loads(response.read().decode('utf-8'))
                self._session_id = result.get('sessionId')
                
                SessionManager.store_session(self._session_id)
                threading.Thread(target=self.fetch_accounts, daemon=True).start()
        except Exception as e:
            traceback.print_exc()
    
    def fetch_accounts_sync(self):
        url = "https://auth.jagex.com/game-session/v1/accounts"
        
        request = Request(url, method='GET')
        request.add_header('Content-Type', 'application/json')
        request.add_header('Accept', 'application/json')
        request.add_header('Authorization', f'Bearer {self._session_id}')
        
        with urlopen(request) as response:
            return json.loads(response.read().decode('utf-8'))
    
    def fetch_accounts(self):
        try:
            self._accounts = self.fetch_accounts_sync()
            GLib.idle_add(self.show_character_selection)
        except Exception as e:
            traceback.print_exc()
    
    def show_character_selection(self):
        old_view = self.stack.get_child_by_name("characters")
        if old_view:
            self.stack.remove(old_view)
        
        self.back_button.set_visible(False)
        self.sign_out_action.set_enabled(True)
        
        char_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=30)
        char_box.set_halign(Gtk.Align.CENTER)
        char_box.set_valign(Gtk.Align.CENTER)
        char_box.set_margin_top(40)
        char_box.set_margin_bottom(40)
        char_box.set_margin_start(40)
        char_box.set_margin_end(40)
        
        dropdown_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        dropdown_box.set_size_request(300, -1)
        
        label = Gtk.Label(label="Character")
        label.set_halign(Gtk.Align.START)
        dropdown_box.append(label)
        
        string_list = Gtk.StringList()
        for account in self._accounts:
            display = account.get('displayName') or account['accountId']
            string_list.append(display)
        
        self.character_dropdown = Gtk.DropDown(model=string_list)
        self.character_dropdown.set_selected(0)
        dropdown_box.append(self.character_dropdown)
        
        char_box.append(dropdown_box)
        
        client_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        client_box.set_size_request(300, -1)
        
        client_label = Gtk.Label(label="Client")
        client_label.set_halign(Gtk.Align.START)
        client_box.append(client_label)
        
        client_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        
        client_string_list = Gtk.StringList()
        for client_name in self._client_names:
            client_string_list.append(client_name)
        
        self.client_dropdown = Gtk.DropDown(model=client_string_list)
        self.client_dropdown.set_hexpand(True)

        last_client = self._settings.get_string("last-client")
        if last_client in self._client_names:
            self.client_dropdown.set_selected(self._client_names.index(last_client))
        else:
            self.client_dropdown.set_selected(0)
        client_row.append(self.client_dropdown)
        
        self.delete_btn = Gtk.Button(icon_name="user-trash-symbolic")
        self.delete_btn.add_css_class("destructive-action")
        self.delete_btn.set_tooltip_text("Delete client")
        self.delete_btn.connect("clicked", self.on_delete_client_clicked)
        client_row.append(self.delete_btn)

        self.client_dropdown.connect("notify::selected", self.on_client_changed)
        
        client_box.append(client_row)
        char_box.append(client_box)
        
        self.update_delete_button_visibility()
        
        play_btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        play_btn_box.set_halign(Gtk.Align.CENTER)
        
        play_icon = Gtk.Image.new_from_icon_name("media-playback-start-symbolic")
        play_btn_box.append(play_icon)
        
        play_label = Gtk.Label(label="Launch")
        play_btn_box.append(play_label)
        
        play_btn = Gtk.Button()
        play_btn.set_child(play_btn_box)
        play_btn.add_css_class("suggested-action")
        play_btn.add_css_class("pill")
        play_btn.set_size_request(200, 50)
        play_btn.connect('clicked', self.on_play_clicked)
        char_box.append(play_btn)
        
        self.stack.add_named(char_box, "characters")
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
            button.set_label("Downloading...")
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
            def restore_button():
                play_btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                play_btn_box.set_halign(Gtk.Align.CENTER)
                play_icon = Gtk.Image.new_from_icon_name("media-playback-start-symbolic")
                play_btn_box.append(play_icon)
                play_label = Gtk.Label(label="Launch")
                play_btn_box.append(play_label)
                button.set_child(play_btn_box)
            GLib.idle_add(restore_button)
    
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
        old_view = self.stack.get_child_by_name("settings")
        if old_view:
            self.stack.remove(old_view)
        
        self.back_button.set_visible(True)
        
        settings_page = Adw.PreferencesPage()
        
        general_group = Adw.PreferencesGroup()
        general_group.set_title("General")
        
        close_after_launch_row = Adw.SwitchRow()
        close_after_launch_row.set_title("Close launcher after launching game")
        close_after_launch_row.set_subtitle("Automatically close the launcher when a game client is started")
        close_after_launch_row.set_active(self._settings.get_boolean("close-after-launch"))
        close_after_launch_row.connect("notify::active", self.on_close_after_launch_changed)
        general_group.add(close_after_launch_row)
        
        java_path_row = Adw.EntryRow()
        java_path_row.set_title("Java binary path")
        java_path = self._settings.get_string("java-path")
        java_path_row.set_text(java_path if java_path else "java")
        java_path_row.connect("apply", self.on_java_path_changed)
        java_path_row.connect("entry-activated", self.on_java_path_changed)
        general_group.add(java_path_row)
        
        settings_page.add(general_group)
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.set_child(settings_page)
        
        self.stack.add_named(scrolled, "settings")
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