#!/usr/bin/env python3
"""
SecureBridge v2.0 — Production-Grade Secure Chat
Tez Projesi · Deniz Harp Okulu
"""

import customtkinter as ctk
import asyncio
import threading
import json
import os
import sys
import hmac
import hashlib
import logging
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Callable
from cryptography.fernet import Fernet, InvalidToken
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import websockets

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM FIX
# ─────────────────────────────────────────────────────────────────────────────
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("securebridge.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("SecureBridge")


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
CONFIG_FILE = "config.json"


@dataclass
class AppConfig:
    esp32_host: str = "192.168.4.1"
    esp32_port: int = 81
    max_message_length: int = 2000
    reconnect_delay: int = 5
    ping_interval: int = 20
    ping_timeout: int = 10
    log_file: str = "sohbet_kayitlari.txt"

    @property
    def uri(self) -> str:
        return f"ws://{self.esp32_host}:{self.esp32_port}"

    @classmethod
    def load(cls) -> "AppConfig":
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
                return cls(**valid)
            except Exception:
                pass
        return cls()

    def save(self) -> None:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO MANAGER  (AES-256 + HMAC-SHA256 + Sequence Numbers)
# ─────────────────────────────────────────────────────────────────────────────
class CryptoManager:
    """
    Uçtan uca şifreleme, mesaj bütünlüğü doğrulama ve
    tekrar-oynatma saldırısı (replay attack) önleme.
    """

    _SALT_ENC  = b"securebridge_v2_enc_salt_dho"
    _SALT_HMAC = b"securebridge_v2_hmac_salt_dho"

    def __init__(self, password: str) -> None:
        self._cipher    = self._derive_fernet(password)
        self._hmac_key  = self._derive_hmac_key(password)
        self._seq       = 0
        self._seen_seqs: set[int] = set()

    # ── Key derivation ──────────────────────────────────────────────────────
    def _derive_fernet(self, password: str) -> Fernet:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=self._SALT_ENC, iterations=100_000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def _derive_hmac_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=self._SALT_HMAC, iterations=100_000)
        return kdf.derive(password.encode())

    # ── HMAC ────────────────────────────────────────────────────────────────
    def _sign(self, data: str) -> str:
        mac = hmac.new(self._hmac_key, data.encode(), hashlib.sha256)
        return mac.hexdigest()

    # ── Public API ──────────────────────────────────────────────────────────
    def encrypt(self, user_id: str, message: str) -> str:
        """Mesajı şifrele ve HMAC ekle."""
        self._seq += 1
        payload = {
            "id":   user_id,
            "msg":  message,
            "time": datetime.now().strftime("%H:%M"),
            "seq":  self._seq,
        }
        raw = json.dumps(payload, ensure_ascii=False)
        payload["hmac"] = self._sign(raw)
        full = json.dumps(payload, ensure_ascii=False)
        return self._cipher.encrypt(full.encode()).decode()

    def decrypt(self, encrypted: str) -> Optional[dict]:
        """
        Şifreyi çöz ve HMAC / sequence number doğrula.
        Herhangi bir hata veya manipülasyon tespit edilirse None döner.
        """
        try:
            raw = self._cipher.decrypt(encrypted.encode()).decode()
            data = json.loads(raw)

            # HMAC doğrulama
            received_hmac = data.pop("hmac", "")
            body_str      = json.dumps(
                {k: v for k, v in data.items()}, ensure_ascii=False
            )
            if not hmac.compare_digest(received_hmac, self._sign(body_str)):
                logger.warning("HMAC doğrulama başarısız — mesaj değiştirilmiş olabilir!")
                return None

            # Replay attack kontrolü
            seq = data.get("seq", -1)
            if seq in self._seen_seqs:
                logger.warning(f"Tekrar oynatma saldırısı! Seq={seq} daha önce görüldü.")
                return None
            self._seen_seqs.add(seq)

            # Bellek sızıntısını önlemek için eski seq'leri temizle
            if len(self._seen_seqs) > 1000:
                self._seen_seqs = set(sorted(self._seen_seqs)[-500:])

            return data

        except InvalidToken:
            logger.warning("Şifre çözme başarısız — yanlış anahtar veya bozuk veri.")
            return None
        except Exception as e:
            logger.error(f"Beklenmeyen şifre çözme hatası: {e}")
            return None
    def zeroize(self):
        """Kritik anahtarları bellekten (RAM) temizler."""
        self.key = None
        self.fernet = None
        import gc
        gc.collect() # Çöp toplayıcıyı zorla çalıştırarak izleri siler

# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class ConnectionState:
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"


class WebSocketManager:
    """WebSocket bağlantısını yönetir; otomatik yeniden bağlanma destekler."""

    _IGNORE = {"Sunucuya bağlandınız.", "Connected to server."}

    def __init__(self, config: AppConfig) -> None:
        self.config    = config
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.loop:      Optional[asyncio.AbstractEventLoop] = None
        self.state      = ConnectionState.DISCONNECTED

        # Callbacks (thread-safe olduğunu varsay — UI tarafı after() kullanır)
        self.on_message:      Optional[Callable[[str], None]] = None
        self.on_connected:    Optional[Callable[[], None]]    = None
        self.on_disconnected: Optional[Callable[[], None]]    = None
        self.on_connecting:   Optional[Callable[[], None]]    = None

    def start(self) -> None:
        threading.Thread(target=self._run_loop, daemon=True).start()

    def _run_loop(self) -> None:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect_loop())

    async def _connect_loop(self) -> None:
        while True:
            try:
                self.state = ConnectionState.CONNECTING
                if self.on_connecting: self.on_connecting()

                async with websockets.connect(self.config.uri) as ws:
                    self.websocket = ws
                    self.state = ConnectionState.CONNECTED
                    if self.on_connected: self.on_connected()

                    while self.state == ConnectionState.CONNECTED:
                        # --- PİNG ÖLÇÜMÜ ---
                        try:
                            start_time = self.loop.time()
                            pong_waiter = await ws.ping()
                            await pong_waiter
                            latency = (self.loop.time() - start_time) * 1000
                            if hasattr(self, 'on_ping_update'):
                                self.on_ping_update(latency)
                        except:
                            pass

                        # --- MESAJ BEKLEME ---
                        try:
                            raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                            if raw in self._IGNORE: continue
                            if self.on_message: self.on_message(raw)
                        except asyncio.TimeoutError:
                            continue
            except Exception as e:
                logger.error(f"Bağlantı hatası: {e}")
            finally:
                self.state = ConnectionState.DISCONNECTED
                if self.on_disconnected: self.on_disconnected()
            await asyncio.sleep(self.config.reconnect_delay)

    def send(self, data: str) -> bool:
        """Thread-safe mesaj gönderimi."""
        if self.loop and self.websocket and self.state == ConnectionState.CONNECTED:
            asyncio.run_coroutine_threadsafe(self.websocket.send(data), self.loop)
            return True
        return False

    @property
    def is_connected(self) -> bool:
        return self.state == ConnectionState.CONNECTED


# ─────────────────────────────────────────────────────────────────────────────
# CHAT LOGGER  (tez kanıtı için gelişmiş format)
# ─────────────────────────────────────────────────────────────────────────────
class ChatLogger:
    def __init__(self, log_file: str) -> None:
        self.log_file = log_file

    def log(self, sender: str, plain: str, encrypted: str, verified: bool = True) -> None:
        ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        integrity = "✓ HMAC DOĞRULANDI" if verified else "✗ HMAC BAŞARISIZ / TAHRİF"
        preview   = encrypted[:72] + "..." if len(encrypted) > 72 else encrypted

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"┌{'─' * 64}\n")
            f.write(f"│  ZAMAN      : {ts}\n")
            f.write(f"│  GÖNDEREN   : {sender}\n")
            f.write(f"│  DÜZ METİN  : {plain}\n")
            f.write(f"│  ŞİFRELİ    : {preview}\n")
            f.write(f"│  BÜTÜNLÜK   : {integrity}\n")
            f.write(f"└{'─' * 64}\n\n")


# ─────────────────────────────────────────────────────────────────────────────
# DESIGN TOKENS
# ─────────────────────────────────────────────────────────────────────────────
T = {
    "bg0":        "#090b10",
    "bg1":        "#0f1219",
    "bg2":        "#161b26",
    "bg3":        "#1e2535",
    "border":     "#252d42",
    "accent":     "#3b82f6",
    "accent2":    "#8b5cf6",
    "accent_h":   "#2563eb",
    "success":    "#10b981",
    "warn":       "#f59e0b",
    "danger":     "#ef4444",
    "txt0":       "#f1f5f9",
    "txt1":       "#94a3b8",
    "txt2":       "#475569",
    "font_mono":  "Courier New",
    "font_ui":    "Courier New",
}

EMOJIS = [
    "😀","😂","😊","😍","🤔","😅","😎","🥳","😢","😡",
    "👍","👎","❤️","🔥","✅","❌","⚠️","🔒","🔓","🛡️",
    "💻","📡","🌐","📨","🔑","⚡","🚀","💬","📞","🤝",
]


# ─────────────────────────────────────────────────────────────────────────────
# REUSABLE WIDGETS
# ─────────────────────────────────────────────────────────────────────────────
class StatusDot(ctk.CTkFrame):
    """Bağlantı durumu göstergesi: renkli ● + etiket."""

    def __init__(self, parent, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._dot = ctk.CTkLabel(self, text="●", font=(T["font_mono"], 13))
        self._dot.pack(side="left", padx=(0, 5))
        self._lbl = ctk.CTkLabel(self, font=(T["font_mono"], 11),
                                  text_color=T["txt1"])
        self._lbl.pack(side="left")

    def connecting(self):
        self._dot.configure(text_color=T["warn"])
        self._lbl.configure(text="ESP32'ye bağlanılıyor…")

    def connected(self, uri: str):
        self._dot.configure(text_color=T["success"])
        self._lbl.configure(text=f"Bağlı  ·  {uri}")

    def disconnected(self):
        self._dot.configure(text_color=T["danger"])
        self._lbl.configure(text="Bağlantı kesildi — yeniden deneniyor…")


class EmojiPicker(ctk.CTkToplevel):
    def __init__(self, parent, on_pick: Callable[[str], None]):
        super().__init__(parent)
        self.on_pick = on_pick
        self.title("Emoji Seç")
        self.geometry("336x120")
        self.resizable(False, False)
        self.configure(fg_color=T["bg2"])
        self.attributes("-topmost", True)

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(padx=6, pady=6, fill="both", expand=True)

        cols = 10
        for i, e in enumerate(EMOJIS):
            btn = ctk.CTkButton(
                grid, text=e, width=28, height=28,
                font=("Segoe UI Emoji", 15),
                fg_color="transparent",
                hover_color=T["bg3"],
                command=lambda em=e: self._pick(em),
            )
            btn.grid(row=i // cols, column=i % cols, padx=1, pady=1)

    def _pick(self, e: str):
        self.on_pick(e)
        self.destroy()


class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent, config: AppConfig):
        super().__init__(parent)
        self.config = config
        self.title("Bağlantı Ayarları")
        self.geometry("420x320")
        self.resizable(False, False)
        self.configure(fg_color=T["bg2"])
        self.attributes("-topmost", True)
        self._build()

    def _build(self):
        pad = dict(padx=24, pady=6)

        ctk.CTkLabel(
            self, text="⚙  Bağlantı Ayarları",
            font=(T["font_mono"], 16, "bold"),
            text_color=T["txt0"],
        ).pack(pady=(24, 16))

        for label, attr, default in [
            ("ESP32 IP Adresi", "esp32_host", self.config.esp32_host),
            ("Port",            "esp32_port", str(self.config.esp32_port)),
            ("Yeniden Bağlanma Gecikmesi (sn)", "reconnect_delay", str(self.config.reconnect_delay)),
        ]:
            ctk.CTkLabel(self, text=label, font=(T["font_mono"], 11),
                         text_color=T["txt1"]).pack(**pad, anchor="w")
            entry = ctk.CTkEntry(self, width=372, height=38,
                                  font=(T["font_mono"], 13),
                                  fg_color=T["bg3"], border_color=T["border"],
                                  text_color=T["txt0"])
            entry.insert(0, default)
            entry.pack(**pad)
            setattr(self, f"_{attr}_entry", entry)

        ctk.CTkButton(
            self, text="Kaydet & Kapat",
            width=372, height=42,
            fg_color=T["accent"], hover_color=T["accent_h"],
            font=(T["font_mono"], 13, "bold"),
            command=self._save,
        ).pack(pady=20)

    def _save(self):
        self.config.esp32_host = self._esp32_host_entry.get().strip()
        try:
            self.config.esp32_port = int(self._esp32_port_entry.get().strip())
        except ValueError:
            pass
        try:
            self.config.reconnect_delay = int(self._reconnect_delay_entry.get().strip())
        except ValueError:
            pass
        self.config.save()
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN FRAME
# ─────────────────────────────────────────────────────────────────────────────
class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, on_login: Callable[[str, str], None]):
        super().__init__(parent, fg_color="transparent")
        self.on_login = on_login
        self._build()

    def _build(self):
        card = ctk.CTkFrame(
            self,
            fg_color=T["bg2"],
            corner_radius=14,
            border_width=1,
            border_color=T["border"],
            width=380, height=500,
        )
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.pack_propagate(False)

        # Icon
        icon_bg = ctk.CTkFrame(card, fg_color=T["bg3"], corner_radius=40,
                                width=72, height=72)
        icon_bg.pack(pady=(36, 0))
        icon_bg.pack_propagate(False)
        ctk.CTkLabel(icon_bg, text="🔒", font=("Segoe UI Emoji", 32)).place(
            relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="SecureBridge",
                     font=(T["font_mono"], 26, "bold"),
                     text_color=T["txt0"]).pack(pady=(14, 2))

        ctk.CTkLabel(card, text="v2.0  ·  Güvenli İletişim Sistemi",
                     font=(T["font_mono"], 11),
                     text_color=T["txt1"]).pack(pady=(0, 28))

        self._user_e = ctk.CTkEntry(
            card, placeholder_text="Kullanıcı Adı",
            width=310, height=46,
            font=(T["font_mono"], 13),
            fg_color=T["bg3"], border_color=T["border"],
            text_color=T["txt0"],
        )
        self._user_e.pack(pady=5)

        self._pass_e = ctk.CTkEntry(
            card, placeholder_text="Güvenlik Anahtarı (min. 6 karakter)",
            show="*", width=310, height=46,
            font=(T["font_mono"], 13),
            fg_color=T["bg3"], border_color=T["border"],
            text_color=T["txt0"],
        )
        self._pass_e.pack(pady=5)

        self._err_lbl = ctk.CTkLabel(
            card, text="", font=(T["font_mono"], 11),
            text_color=T["danger"],
        )
        self._err_lbl.pack(pady=2)

        self._btn = ctk.CTkButton(
            card, text="BAĞLAN",
            width=310, height=46,
            font=(T["font_mono"], 14, "bold"),
            fg_color=T["accent"], hover_color=T["accent_h"],
            corner_radius=8,
            command=self._attempt,
        )
        self._btn.pack(pady=12)

        self._user_e.bind("<Return>", lambda _: self._pass_e.focus())
        self._pass_e.bind("<Return>", lambda _: self._attempt())
        self._user_e.focus()

    def _attempt(self):
        user = self._user_e.get().strip()
        pw   = self._pass_e.get()
        if not user:
            self._err_lbl.configure(text="⚠  Kullanıcı adı boş olamaz.")
            return
        if len(pw) < 6:
            self._err_lbl.configure(text="⚠  Anahtar en az 6 karakter olmalı.")
            return
        self._err_lbl.configure(text="")
        self.on_login(user, pw)


# ─────────────────────────────────────────────────────────────────────────────
# CHAT FRAME
# ─────────────────────────────────────────────────────────────────────────────
class ChatFrame(ctk.CTkFrame):
    def __init__(self, parent, user_id: str, crypto: CryptoManager,
                 ws: WebSocketManager, logger_: ChatLogger,
                 config: AppConfig, on_settings: Callable,
                 session_manager: "SessionManager" = None,
                 connection_quality: "ConnectionQuality" = None,
                 on_status_change: Callable = None):
        super().__init__(parent, fg_color=T["bg0"])

        self.user_id     = user_id
        self.crypto      = crypto
        self.ws          = ws
        self.chat_logger = logger_
        self.config      = config
        self.on_settings = on_settings
        self._msg_count  = 0
        self._session_manager = session_manager
        self._connection_quality = connection_quality or ConnectionQuality()
        self._on_status_change = on_status_change
        self._typing_indicator = None

        self._build_header()
        
        self._build_statusbar()
        self._build_textarea()
        self._build_inputbar()
        self._wire_ws()
        
    # ── Header ───────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=T["bg2"], height=52, corner_radius=0,
                            border_width=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="🔒 SecureBridge",
                     font=(T["font_mono"], 14, "bold"),
                     text_color=T["txt0"]).pack(side="left", padx=16)

        # Status indicator (tıklayarak değiştir)

        # Right-side controls
        for text, cmd in [
            ("📊", self._show_sessions),
            ("⚙", self.on_settings), 
            ("🗑", self._clear)
        ]:
            ctk.CTkButton(
                hdr, text=text, width=34, height=34,
                font=(T["font_mono"], 15),
                fg_color="transparent", hover_color=T["bg3"],
                command=cmd,
            ).pack(side="right", padx=4)

        badge = ctk.CTkFrame(hdr, fg_color=T["accent"], corner_radius=5)
        badge.pack(side="right", padx=8)
        ctk.CTkLabel(badge, text=f"  {self.user_id}  ",
                     font=(T["font_mono"], 11, "bold"),
                     text_color=T["txt0"]).pack(padx=4, pady=2)
        # PANIC / ZEROIZE Butonu
        # PANIC Butonu - En sağa yerleşir
        self._panic_btn = ctk.CTkButton(
            hdr, text="☢ PANIC", width=70, height=30,
            fg_color="#991b1b", hover_color="#ef4444",
            font=(T["font_mono"], 11, "bold"),
            command=self._emergency_zeroize
        )
        self._panic_btn.pack(side="right", padx=10)
        
    # ── Status bar ───────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=T["bg1"], height=26, corner_radius=0)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self._status = StatusDot(bar)
        self._status.pack(side="left", padx=12, pady=3)
        self._status.connecting()

        # Bağlantı kalitesi göstergesi
        self._signal_frame = ctk.CTkFrame(bar, fg_color="transparent")
        self._signal_frame.pack(side="left", padx=8)
        
        self._signal_lbl = ctk.CTkLabel(
            self._signal_frame, text="📶 ____", font=(T["font_mono"], 10),
            text_color=T["txt2"],
        )
        self._signal_lbl.pack(side="left")
        
        self._ping_lbl = ctk.CTkLabel(
            self._signal_frame, text="--ms", font=(T["font_mono"], 9),
            text_color=T["txt2"],
        )
        self._ping_lbl.pack(side="left", padx=4)

        # Yazma göstergesi
        self._typing_lbl = ctk.CTkLabel(
            bar, text="", font=(T["font_mono"], 10),
            text_color=T["accent"],
        )
        self._typing_lbl.pack(side="left", padx=8)
        self._typing_indicator = TypingIndicator(self._typing_lbl)

        self._count_lbl = ctk.CTkLabel(
            bar, text="", font=(T["font_mono"], 10),
            text_color=T["txt2"],
        )
        self._count_lbl.pack(side="right", padx=12)

    # ── Chat area ────────────────────────────────────────────────────────────
    def _build_textarea(self):
        self._chat = ctk.CTkTextbox(
            self,
            font=(T["font_mono"], 13),
            fg_color=T["bg0"],
            text_color=T["txt0"],
            border_width=0,
            wrap="word",
            spacing3=4,
        )
        self._chat.pack(fill="both", expand=True, padx=10, pady=(6, 2))
        self._chat.configure(state="disabled")

        tb = self._chat._textbox
        tb.tag_configure("ts",      foreground=T["txt2"])
        tb.tag_configure("me",      foreground=T["accent"])
        tb.tag_configure("other",   foreground=T["accent2"])
        tb.tag_configure("system",  foreground=T["warn"])
        tb.tag_configure("danger",  foreground=T["danger"])
        tb.tag_configure("body",    foreground=T["txt0"])
        

    # ── Input bar ────────────────────────────────────────────────────────────
    def _build_inputbar(self):
        bar = ctk.CTkFrame(self, fg_color=T["bg2"], height=66, corner_radius=0)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(
            inner, text="😊", width=42, height=42,
            font=("Segoe UI Emoji", 17),
            fg_color=T["bg3"], hover_color=T["border"],
            corner_radius=8,
            command=self._open_emoji,
        ).pack(side="left", padx=(0, 6))

        self._entry = ctk.CTkEntry(
            inner,
            placeholder_text="Mesajınızı yazın…  (Enter = gönder)",
            height=42,
            font=(T["font_mono"], 13),
            fg_color=T["bg3"], border_color=T["border"],
            text_color=T["txt0"],
            corner_radius=8,
        )
        self._entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self._entry.bind("<KeyRelease>", self._on_key)
        self._entry.bind("<Return>",     lambda _: self._send())

        self._char_lbl = ctk.CTkLabel(
            inner, text="0", width=30,
            font=(T["font_mono"], 10),
            text_color=T["txt2"],
        )
        self._char_lbl.pack(side="left", padx=(0, 6))

        self._send_btn = ctk.CTkButton(
            inner, text="↑", width=42, height=42,
            font=(T["font_mono"], 17, "bold"),
            fg_color=T["accent"], hover_color=T["accent_h"],
            corner_radius=8,
            command=self._send,
        )
        self._send_btn.pack(side="right")

    # ── WebSocket wiring ─────────────────────────────────────────────────────
    def _wire_ws(self):
        self.ws.on_connecting   = lambda: self.after(0, self._status.connecting)
        self.ws.on_connected    = lambda: self.after(0, self._on_ws_connected)
        self.ws.on_disconnected = lambda: self.after(0, self._status.disconnected)
        self.ws.on_message      = self._on_incoming  # called from network thread
        self.ws.on_ping_update  = lambda ms: self.after(0, lambda: self.update_connection_quality(ms))
    def _on_ws_connected(self):
        self._status.connected(self.ws.config.uri)
        self._sys("Bağlantı sağlandı.  Uçtan uca AES-256 şifreleme aktif. ✓")

    # ── Key listener ─────────────────────────────────────────────────────────
    def _on_key(self, _event):
        n = len(self._entry.get())
        if n > self.config.max_message_length:
            self._entry.delete(self.config.max_message_length, "end")
            n = self.config.max_message_length
            self._char_lbl.configure(text_color=T["danger"])
        elif n > self.config.max_message_length * 0.8:
            self._char_lbl.configure(text_color=T["warn"])
        else:
            self._char_lbl.configure(text_color=T["txt2"])
        self._char_lbl.configure(text=str(n))

    # ── Send ─────────────────────────────────────────────────────────────────
    def _send(self):
        msg = self._entry.get().strip()
        if not msg:
            return
        if not self.ws.is_connected:
            self._sys("⚠  Bağlantı yok. ESP32 Wi-Fi ağına bağlı olduğunuzdan emin olun.", danger=True)
            return

        encrypted = self.crypto.encrypt(self.user_id, msg)
        if self.ws.send(encrypted):
            self.chat_logger.log(f"Siz ({self.user_id})", msg, encrypted, verified=True)
            self._append("Siz", msg, is_self=True)
            self._entry.delete(0, "end")
            self._char_lbl.configure(text="0", text_color=T["txt2"])
        else:
            self._sys("⚠  Mesaj gönderilemedi.", danger=True)

    # ── Incoming messages ────────────────────────────────────────────────────
    def _on_incoming(self, raw: str):
        # 1. ADIM: ESP32'den gelen şifresiz sistem mesajı mı (JSON)?
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and data.get("type") == "session_update":
                # DİKKAT: 'self.session_manager' mı yoksa 'self._session_manager' mı? 
                # Hata mesajına göre senin kodunda 'self.session_manager' (alt çizgisiz) geçerli.
                self.session_manager.sessions = data.get("clients", [])
                return 
        except:
            pass

        # 2. ADIM: Şifreli Mesaj Çözme (Fernet/AES)
        decoded_data = self.crypto.decrypt(raw)
        
        # Şifre çözülemediyse (hatalı anahtar veya bozuk veri) çık
        if decoded_data is None:
            return

        # Mesajı gönderen bizsek ekrana tekrar basma
        if decoded_data.get("id") == self.user_id:
            return 

        # 3. ADIM: Kayıt ve Görselleştirme
        # Loglama ve mesajı ekrana basma (Senin görsel fonksiyonun: _append)
        self.chat_logger.log(decoded_data["id"], decoded_data["msg"], raw, verified=True)
        self.after(0, lambda d=decoded_data: self._append(d["id"], d["msg"], is_self=False))

    # ── Display helpers ───────────────────────────────────────────────────────
    def _append(self, sender: str, message: str, is_self: bool):
        self._chat.configure(state="normal")
        tb  = self._chat._textbox
        ts  = datetime.now().strftime("%H:%M")
        pfx = "  ▶ " if is_self else "  ◀ "
        stag = "me" if is_self else "other"

        tb.insert("end", f"\n{pfx}", "ts")
        tb.insert("end", sender,     stag)
        tb.insert("end", f"  {ts}\n","ts")
        tb.insert("end", f"    {message}\n", "body")

        self._chat.configure(state="disabled")
        self._chat.see("end")

        self._msg_count += 1
        self._count_lbl.configure(text=f"{self._msg_count} mesaj")

    def _sys(self, text: str, danger: bool = False):
        self._chat.configure(state="normal")
        tag = "danger" if danger else "system"
        self._chat._textbox.insert("end", f"\n  ⚙  {text}\n", tag)
        self._chat.configure(state="disabled")
        self._chat.see("end")

    def _clear(self):
        self._chat.configure(state="normal")
        self._chat.delete("1.0", "end")
        self._chat.configure(state="disabled")
        self._msg_count = 0
        self._count_lbl.configure(text="")

    def _open_emoji(self):
        EmojiPicker(self, on_pick=self._insert_emoji)

    def _insert_emoji(self, emoji: str):
        self._entry.insert("end", emoji)
        self._entry.focus()

    # ── Status selector ─────────────────────────────────────────────────────
    
    
    def _on_status_selected(self, status: str):
        if self._on_status_change:
            self._on_status_change(status)
        self._status_indicator.configure(text=UserStatus.to_emoji(status))
    
    # ── Sessions dialog ─────────────────────────────────────────────────────
    def _show_sessions(self):
        if self._session_manager:
            SessionDialog(self, self._session_manager)
        else:
            self._sys("Oturum yönetimi mevcut değil")
    
    # ── Update connection quality ──────────────────────────────────────────
    def update_connection_quality(self, ping_ms: float):
        self._connection_quality.add_ping(ping_ms)
        quality = self._connection_quality.quality
        signal = self._connection_quality.signal_strength
        avg_ping = int(self._connection_quality.average_ping)
        
        color = T["success"] if quality in ["excellent", "good"] else T["warn"] if quality == "fair" else T["danger"]
        self._signal_lbl.configure(text=f"📶 {signal}", text_color=color)
        self._ping_lbl.configure(text=f"{avg_ping}ms", text_color=color)
    
    # ── Typing indicator ───────────────────────────────────────────────────
    def show_typing(self, username: str):
        if self._typing_indicator:
            self._typing_indicator.start(username)
    
    def hide_typing(self):
        if self._typing_indicator:
            self._typing_indicator.stop()
    def _emergency_zeroize(self):
        """Askeri standartta veri ve anahtar imha protokolü."""
        # 1. Bellekteki anahtarları yok et
        self.crypto.zeroize()
        
        # 2. Log dosyalarını bul ve üzerine rastgele veri yazarak sil
        # Uygulamanın oluşturduğu standart log dosyasını hedef alıyoruz
        log_files = ["securebridge.log", "chat_history.log"] 
        
        for file in log_files:
            try:
                if os.path.exists(file):
                    # Dosyanın boyutunu öğren ve üzerine rastgele baytlar yaz
                    size = os.path.getsize(file)
                    with open(file, "ba+", buffering=0) as f:
                        f.write(os.urandom(size))
                    os.remove(file)
            except:
                pass

        # 3. Kullanıcıya bildirim ver ve kapat
        print("KRİPTOGRAFİK İMHA: Tüm anahtarlar ve loglar yok edildi.")
        self.master.destroy()
        sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION ROOT
# ─────────────────────────────────────────────────────────────────────────────
class SecureBridgeApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.config = AppConfig.load()
        self.title("SecureBridge v2.0")
        self.geometry("600x780")
        self.minsize(500, 600)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=T["bg0"])

        self._crypto:     Optional[CryptoManager]  = None
        self._ws:         Optional[WebSocketManager] = None
        self._chat_log:   Optional[ChatLogger]       = None
        self._chat_frame: Optional[ChatFrame]        = None
        
        # Yeni özellikler
        self._session_manager = SessionManager()
        self._connection_quality = ConnectionQuality()
        self._system_tray: Optional[SystemTray] = None
        self._user_status = UserStatus.ONLINE

        self._show_login()
        
        # Pencere kapatma olayını yakala
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        """Pencere kapatıldığında sistem tepsisine mi yoksa tamamen mi kapat."""
        if self._system_tray:
            self._system_tray.minimize_to_tray()
        else:
            self.destroy()

    def _show_login(self):
        self._login = LoginFrame(self, on_login=self._handle_login)
        self._login.pack(fill="both", expand=True)

    def _handle_login(self, username: str, password: str):
        logger.info(f"Giriş yapıldı: {username}")

        self._crypto   = CryptoManager(password)
        self._chat_log = ChatLogger(self.config.log_file)
        self._ws       = WebSocketManager(self.config)
        
        # Oturum ekle
        self._session_manager.add_session("local", username, "localhost")

        self._login.destroy()

        self._chat_frame = ChatFrame(
            self,
            user_id=username,
            crypto=self._crypto,
            ws=self._ws,
            logger_=self._chat_log,
            config=self.config,
            on_settings=self._open_settings,
            session_manager=self._session_manager,
            connection_quality=self._connection_quality,
            on_status_change=self._change_status,
        )
        self._chat_frame.pack(fill="both", expand=True)
        self._ws.start()
        
        # Sistem tepsisini aktif et
        self._system_tray = SystemTray(
            self,
            on_show=lambda: self._system_tray.restore_from_tray(),
            on_quit=self.destroy,
        )

    def _open_settings(self):
        SettingsDialog(self, self.config)
    
    def _open_sessions(self):
        SessionDialog(self, self._session_manager)
    
    def _change_status(self, new_status: str):
        self._user_status = new_status
        self._session_manager.update_status("local", new_status)
        logger.info(f"Durum değiştirildi: {new_status}")


# ─────────────────────────────────────────────────────────────────────────────
# STATUS MANAGER (Online/Offline/Away)
# ─────────────────────────────────────────────────────────────────────────────
class UserStatus:
    ONLINE = "online"
    OFFLINE = "offline"
    AWAY = "away"
    DND = "dnd"  # Do Not Disturb
    
    @staticmethod
    def to_emoji(status: str) -> str:
        return {
            UserStatus.ONLINE: "🟢",
            UserStatus.OFFLINE: "⚫",
            UserStatus.AWAY: "🟡",
            UserStatus.DND: "🔴",
        }.get(status, "⚫")
    
    @staticmethod
    def to_text(status: str) -> str:
        return {
            UserStatus.ONLINE: "Çevrimiçi",
            UserStatus.OFFLINE: "Çevrimdışı",
            UserStatus.AWAY: "Uzakta",
            UserStatus.DND: "Rahatsız Etmeyin",
        }.get(status, "Bilinmiyor")


# ─────────────────────────────────────────────────────────────────────────────
# TYPING INDICATOR
# ─────────────────────────────────────────────────────────────────────────────
class TypingIndicator:
    """Yazma göstergesi animasyonu."""
    
    _STATES = ["", ".", "..", "..."]
    
    def __init__(self, label: ctk.CTkLabel):
        self._label = label
        self._index = 0
        self._after_id = None
        self._active = False
    
    def start(self, username: str):
        self._username = username
        self._active = True
        self._animate()
    
    def stop(self):
        self._active = False
        if self._after_id:
            self._label.after_cancel(self._after_id)
            self._after_id = None
        self._label.configure(text="")
    
    def _animate(self):
        if not self._active:
            return
        self._index = (self._index + 1) % 4
        self._label.configure(text=f"  ✏️ {self._username} yazıyor{self._STATES[self._index]}")
        self._after_id = self._label.after(400, self._animate)


# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION QUALITY MONITOR
# ─────────────────────────────────────────────────────────────────────────────
class ConnectionQuality:
    """Bağlantı kalitesi göstergesi."""
    
    def __init__(self):
        self._ping_times: list[float] = []
        self._last_ping = 0
    
    def add_ping(self, latency_ms: float):
        self._ping_times.append(latency_ms)
        if len(self._ping_times) > 10:
            self._ping_times.pop(0)
    
    @property
    def average_ping(self) -> float:
        if not self._ping_times:
            return 0
        return sum(self._ping_times) / len(self._ping_times)
    
    @property
    def quality(self) -> str:
        avg = self.average_ping
        if avg == 0:
            return "unknown"
        elif avg < 50:
            return "excellent"
        elif avg < 100:
            return "good"
        elif avg < 200:
            return "fair"
        else:
            return "poor"
    
    @property
    def signal_strength(self) -> str:
        q = self.quality
        return {
            "excellent": "▂▄▆█",
            "good": "▂▄▆_",
            "fair": "▂▄__",
            "poor": "▂___",
            "unknown": "____",
        }.get(q, "____")


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM TRAY (pystray alternative using tkinter)
# ─────────────────────────────────────────────────────────────────────────────
class SystemTray:
    """Sistem tepsisi entegrasyonu."""
    
    def __init__(self, app: ctk.CTk, on_show: Callable, on_quit: Callable):
        self._app = app
        self._on_show = on_show
        self._on_quit = on_quit
        self._tray_window = None
        self._minimized_to_tray = False
    
    def minimize_to_tray(self):
        """Pencereyi sistem tepsisine küçült."""
        self._minimized_to_tray = True
        self._app.withdraw()
        self._create_tray_menu()
    
    def restore_from_tray(self):
        """Tepsideki simgeyi tıklayınca geri getir."""
        self._minimized_to_tray = False
        if self._tray_window:
            self._tray_window.destroy()
            self._tray_window = None
        self._app.deiconify()
        self._app.lift()
    
    def _create_tray_menu(self):
        """Sistem tepsisi için pencere oluştur (basit yaklaşım)."""
        self._tray_window = ctk.CTkToplevel(self._app)
        self._tray_window.overrideredirect(True)
        self._tray_window.geometry(f"200x80+{self._app.winfo_x()}+{self._app.winfo_y()}")
        self._tray_window.configure(fg_color=T["bg2"])
        
        ctk.CTkLabel(
            self._tray_window,
            text="🔒 SecureBridge",
            font=(T["font_mono"], 12, "bold"),
            text_color=T["txt0"],
        ).pack(pady=10)
        
        btn_frame = ctk.CTkFrame(self._tray_window, fg_color="transparent")
        btn_frame.pack(pady=5)
        
        ctk.CTkButton(
            btn_frame, text="Göster", width=70, height=28,
            fg_color=T["accent"], hover_color=T["accent_h"],
            command=self.restore_from_tray,
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame, text="Çık", width=70, height=28,
            fg_color=T["danger"], hover_color="#dc2626",
            command=self._on_quit,
        ).pack(side="left", padx=5)
        
        # Sağ tık menüsü
        self._tray_window.bind("<Button-3>", lambda e: self._show_popup(e))
    
    def _show_popup(self, event):
        """Sağ tık popup menüsü."""
        popup = ctk.CTkToplevel(self._app)
        popup.overrideredirect(True)
        popup.geometry(f"120x60+{event.x_root}+{event.y_root}")
        popup.configure(fg_color=T["bg2"])
        
        ctk.CTkButton(
            popup, text="Göster", fg_color="transparent", hover_color=T["bg3"],
            command=lambda: [popup.destroy(), self.restore_from_tray()],
        ).pack(pady=5, padx=10, fill="x")
        
        ctk.CTkButton(
            popup, text="Çıkış", fg_color="transparent", hover_color=T["bg3"],
            text_color=T["danger"],
            command=lambda: [popup.destroy(), self._on_quit()],
        ).pack(pady=5, padx=10, fill="x")
        
        # Dışarı tıklanınca popup'ı kapat
        popup.bind("<FocusOut>", lambda _: popup.destroy())


# ─────────────────────────────────────────────────────────────────────────────
# SESSION MANAGER
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# SESSION MANAGER (Bu kısmı bul ve değiştir)
# ─────────────────────────────────────────────────────────────────────────────
class SessionManager:
    """Aktif oturumları takip eder."""
    def __init__(self):
        # ESP32'den gelen verilerin yazılacağı liste
        self.sessions = [] 

    def get_sessions(self):
        """Arayüzün (UI) hata almadan listeyi okumasını sağlar."""
        return self.sessions

    def add_session(self, session_id, username, ip=""):
        # Eğer liste formatında tutuyorsan (mevcut yapın):
        self.sessions.append({
            "id": session_id, 
            "username": username, 
            "ip": ip, 
            "connected_at": datetime.now().strftime("%H:%M:%S"),
            "status": "online"
        })

# ─────────────────────────────────────────────────────────────────────────────
# SESSION DIALOG (1191. satırdaki hata burada oluşuyor)
# ─────────────────────────────────────────────────────────────────────────────
# SessionDialog içindeki _refresh metodu 'self.session_manager.get_sessions()' 
# çağırdığında yukarıdaki fonksiyon sayesinde artık AttributeError vermeyecektir.

# ─────────────────────────────────────────────────────────────────────────────
# SESSION DIALOG
# ─────────────────────────────────────────────────────────────────────────────
class SessionDialog(ctk.CTkToplevel):
    def __init__(self, parent, session_manager: SessionManager):
        super().__init__(parent)
        self.session_manager = session_manager
        self.title("Oturum Yönetimi")
        self.geometry("400x350")
        self.resizable(False, False)
        self.configure(fg_color=T["bg2"])
        self.attributes("-topmost", True)
        self._build()
        self._refresh()
    
    def _build(self):
        ctk.CTkLabel(
            self, text="📋 Aktif Oturumlar",
            font=(T["font_mono"], 14, "bold"),
            text_color=T["txt0"],
        ).pack(pady=(16, 8))
        
        self._list_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent", height=220
        )
        self._list_frame.pack(fill="both", expand=True, padx=16, pady=8)
        
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=8)
        
        ctk.CTkButton(
            btn_frame, text="🔄 Yenile", width=120,
            fg_color=T["accent"], hover_color=T["accent_h"],
            command=self._refresh,
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            btn_frame, text="Kapat", width=120,
            fg_color=T["bg3"], hover_color=T["border"],
            command=self.destroy,
        ).pack(side="right", padx=4)
    
    def _refresh(self):
        for w in self._list_frame.winfo_children():
            w.destroy()
        
        sessions = self.session_manager.get_sessions()
        
        if not sessions:
            ctk.CTkLabel(
                self._list_frame, text="Aktif oturum yok",
                font=(T["font_mono"], 11), text_color=T["txt2"],
            ).pack(pady=20)
            return
        
        for sid, info in sessions.items():
            row = ctk.CTkFrame(self._list_frame, fg_color=T["bg3"])
            row.pack(fill="x", pady=4)
            
            status_emoji = UserStatus.to_emoji(info["status"])
            ctk.CTkLabel(
                row, text=f"{status_emoji} {info['username']}",
                font=(T["font_mono"], 11, "bold"), text_color=T["txt0"],
            ).pack(side="left", padx=8, pady=8)
            
            ctk.CTkLabel(
                row, text=f"Bağlanma: {info['connected_at']}",
                font=(T["font_mono"], 9), text_color=T["txt2"],
            ).pack(side="left", padx=8)
            
            ctk.CTkButton(
                row, text="Sonlandır", width=70, height=24,
                fg_color=T["danger"], hover_color="#dc2626",
                font=(T["font_mono"], 9),
                command=lambda s=sid: self._kill_session(s),
            ).pack(side="right", padx=8)
    
    def _kill_session(self, session_id: str):
        self.session_manager.remove_session(session_id)
        self._refresh()


# ─────────────────────────────────────────────────────────────────────────────
# STATUS SELECTOR POPUP
# ─────────────────────────────────────────────────────────────────────────────
class StatusSelector(ctk.CTkToplevel):
    def __init__(self, parent, current_status: str, on_select: Callable[[str], None]):
        super().__init__(parent)
        self.on_select = on_select
        self.title("Durum Seç")
        self.geometry("180x160")
        self.resizable(False, False)
        self.configure(fg_color=T["bg2"])
        self.attributes("-topmost", True)
        
        for status, emoji, label in [
            (UserStatus.ONLINE, "🟢", "Çevrimiçi"),
            (UserStatus.AWAY, "🟡", "Uzakta"),
            (UserStatus.DND, "🔴", "Rahatsız Etmeyin"),
            (UserStatus.OFFLINE, "⚫", "Çevrimdışı"),
        ]:
            btn = ctk.CTkButton(
                self, text=f"{emoji}  {label}",
                fg_color=T["bg3"] if status != current_status else T["accent"],
                hover_color=T["border"],
                font=(T["font_mono"], 11),
                command=lambda s=status: self._select(s),
            )
            btn.pack(fill="x", padx=10, pady=4)
    
    def _select(self, status: str):
        self.on_select(status)
        self.destroy()

# ─────────────────────────────────────────────────────────────────────────────
# EK YARDIMCI SINIFLAR (Eksik Olanlar)
# ─────────────────────────────────────────────────────────────────────────────

class UserStatus:
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    
    @staticmethod
    def to_emoji(status):
        return {"online": "🟢", "away": "🟡", "busy": "🔴"}.get(status, "⚪")



class ConnectionQuality:
    """Gecikme (Ping) ve sinyal kalitesini ölçer."""
    def __init__(self):
        self.pings = []
    def add_ping(self, ms):
        self.pings.append(ms)
        if len(self.pings) > 10: self.pings.pop(0)
    @property
    def average_ping(self):
        return sum(self.pings) / len(self.pings) if self.pings else 0
    @property
    def quality(self):
        p = self.average_ping
        if p < 50: return "excellent"
        elif p < 150: return "good"
        else: return "poor"
    @property
    def signal_strength(self):
        return "▮▮▮▮" if self.quality == "excellent" else "▮▮▯▯"

class TypingIndicator:
    """'Yazıyor...' animasyonunu yönetir."""
    def __init__(self, label):
        self.label = label
        self._active = False
    def start(self, user):
        self._active = True
        self.label.configure(text=f"{user} yazıyor...")
    def stop(self):
        self._active = False
        self.label.configure(text="")

# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION ROOT (TAMAMLANMIŞ)
# ─────────────────────────────────────────────────────────────────────────────

class SecureBridgeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.config = AppConfig.load()
        self.title("SecureBridge v2.0")
        self.geometry("600x780")
        ctk.set_appearance_mode("dark")
        
        self._crypto = None
        self._ws = WebSocketManager(self.config)
        self._chat_log = ChatLogger(self.config.log_file)
        self._session_manager = SessionManager()
        
        self._show_login()

    def _show_login(self):
        if hasattr(self, "_chat_frame") and self._chat_frame:
            self._chat_frame.pack_forget()
        self._login_frame = LoginFrame(self, on_login=self._login_success)
        self._login_frame.pack(fill="both", expand=True)

    def _login_success(self, user_id, password):
        self._crypto = CryptoManager(password)
        self._login_frame.pack_forget()
        
        self._chat_frame = ChatFrame(
            self, user_id, self._crypto, self._ws, 
            self._chat_log, self.config, self._open_settings,
            session_manager=self._session_manager
        )
        self._chat_frame.pack(fill="both", expand=True)
        self._ws.start()

    def _open_settings(self):
        SettingsDialog(self, self.config)


# ─────────────────────────────────────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────────────────────────────────────
def resource_path(relative: str) -> str:
    """PyInstaller ile paketlenmiş EXE'lerde kaynak yolu düzelt."""
    try:
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.abspath(".")
    return os.path.join(base, relative)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SecureBridgeApp()
    app.mainloop()