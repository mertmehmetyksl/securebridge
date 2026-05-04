#!/usr/bin/env python3
"""
SecureBridge v2.0 — Production-Grade Secure Chat
Tez Projesi · Deniz Harp Okulu

Yeni Özellikler:
  - Çok kanallı oda sistemi (ROOM_REGISTRY + özel odalar)
  - Her oda bağımsız AES-256 CryptoManager ile şifreli
  - İki aşamalı oda katılım akışı
  - Mesaj öncelik seviyeleri: NORMAL / ACİL / GİZLİ
  - Sol sidebar: okunmamış badge, aktif oda vurgulama
"""

import gc
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
from dataclasses import dataclass, asdict, field
from typing import Optional, Callable, List, Tuple
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
# ROOM REGISTRY  — sabit oda şifreleri (sıralı)
# 000001 → #genel | 000002 → #operasyon-alfa | 000003 → #şifreli-kanal
# Farklı bir şifre girilirse → kullanıcı özel oda ismi belirler
# ─────────────────────────────────────────────────────────────────────────────
ROOM_REGISTRY: dict = {
    "000001": {
        "name": "genel",
        "icon": "💬",
        "desc": "Genel İletişim Kanalı",
    },
    "000002": {
        "name": "operasyon-alfa",
        "icon": "⚔️",
        "desc": "Operasyonel Komuta Kanalı",
    },
    "000003": {
        "name": "sifreli-kanal",
        "icon": "🛡️",
        "desc": "Maksimum Güvenlik Kanalı",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO MANAGER  (AES-256 + HMAC-SHA256 + Sequence Numbers)
# Payload'a room ve priority alanları eklendi.
# ─────────────────────────────────────────────────────────────────────────────
class CryptoManager:
    """
    Uçtan uca şifreleme, mesaj bütünlüğü doğrulama ve
    tekrar-oynatma saldırısı (replay attack) önleme.
    """

    _SALT_ENC  = b"securebridge_v2_enc_salt_dho"
    _SALT_HMAC = b"securebridge_v2_hmac_salt_dho"

    def __init__(self, password: str) -> None:
        self._cipher   = self._derive_fernet(password)
        self._hmac_key = self._derive_hmac_key(password)
        self._seq      = 0
        self._seen_seqs: set = set()

    def _derive_fernet(self, password: str) -> Fernet:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=self._SALT_ENC, iterations=100_000)
        return Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))

    def _derive_hmac_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=self._SALT_HMAC, iterations=100_000)
        return kdf.derive(password.encode())

    def _sign(self, data: str) -> str:
        mac = hmac.new(self._hmac_key, data.encode(), hashlib.sha256)
        return mac.hexdigest()

    def encrypt(self, user_id: str, message: str,
                room: str = "", priority: str = "normal") -> str:
        """Mesajı oda + öncelik bilgisiyle şifrele."""
        self._seq += 1
        payload = {
            "id":       user_id,
            "msg":      message,
            "time":     datetime.now().strftime("%H:%M"),
            "seq":      self._seq,
            "room":     room,
            "priority": priority,
        }
        raw = json.dumps(payload, ensure_ascii=False)
        payload["hmac"] = self._sign(raw)
        full = json.dumps(payload, ensure_ascii=False)
        return self._cipher.encrypt(full.encode()).decode()

    def decrypt(self, encrypted: str) -> Optional[dict]:
        try:
            raw  = self._cipher.decrypt(encrypted.encode()).decode()
            data = json.loads(raw)

            received_hmac = data.pop("hmac", "")
            body_str = json.dumps({k: v for k, v in data.items()}, ensure_ascii=False)
            if not hmac.compare_digest(received_hmac, self._sign(body_str)):
                logger.warning("HMAC doğrulama başarısız — mesaj değiştirilmiş olabilir!")
                return None

            seq = data.get("seq", -1)
            if seq in self._seen_seqs:
                logger.warning(f"Tekrar oynatma saldırısı! Seq={seq}")
                return None
            self._seen_seqs.add(seq)

            if len(self._seen_seqs) > 1000:
                self._seen_seqs = set(sorted(self._seen_seqs)[-500:])

            return data
        except InvalidToken:
            return None
        except Exception as e:
            logger.error(f"Beklenmeyen şifre çözme hatası: {e}")
            return None

    def zeroize(self):
        self._cipher    = None
        self._hmac_key  = None
        self._seen_seqs = set()
        gc.collect()


# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class ConnectionState:
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"


class WebSocketManager:
    _IGNORE = {"Sunucuya bağlandınız.", "Connected to server."}

    def __init__(self, config: AppConfig) -> None:
        self.config    = config
        self.websocket = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.state     = ConnectionState.DISCONNECTED

        self.on_message:      Optional[Callable] = None
        self.on_connected:    Optional[Callable] = None
        self.on_disconnected: Optional[Callable] = None
        self.on_connecting:   Optional[Callable] = None
        self.on_ping_update:  Optional[Callable] = None

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
                if self.on_connecting:
                    self.on_connecting()

                async with websockets.connect(self.config.uri) as ws:
                    self.websocket = ws
                    self.state = ConnectionState.CONNECTED
                    if self.on_connected:
                        self.on_connected()

                    while self.state == ConnectionState.CONNECTED:
                        try:
                            start = self.loop.time()
                            await (await ws.ping())
                            latency = (self.loop.time() - start) * 1000
                            if self.on_ping_update:
                                self.on_ping_update(latency)
                        except Exception:
                            pass

                        try:
                            raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                            if raw in self._IGNORE:
                                continue
                            if self.on_message:
                                self.on_message(raw)
                        except asyncio.TimeoutError:
                            continue

            except Exception as e:
                logger.error(f"Bağlantı hatası: {e}")
            finally:
                self.state = ConnectionState.DISCONNECTED
                if self.on_disconnected:
                    self.on_disconnected()
            await asyncio.sleep(self.config.reconnect_delay)

    def send(self, data: str) -> bool:
        if self.loop and self.websocket and self.state == ConnectionState.CONNECTED:
            asyncio.run_coroutine_threadsafe(self.websocket.send(data), self.loop)
            return True
        return False

    @property
    def is_connected(self) -> bool:
        return self.state == ConnectionState.CONNECTED


# ─────────────────────────────────────────────────────────────────────────────
# CHAT LOGGER  — oda ve öncelik bilgisi eklendi
# ─────────────────────────────────────────────────────────────────────────────
class ChatLogger:
    def __init__(self, log_file: str) -> None:
        self.log_file = log_file

    def log(self, sender: str, plain: str, encrypted: str,
            room: str = "", priority: str = "normal", verified: bool = True) -> None:
        ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        integrity = "✓ HMAC DOĞRULANDI" if verified else "✗ HMAC BAŞARISIZ / TAHRİF"
        preview   = encrypted[:72] + "..." if len(encrypted) > 72 else encrypted

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"┌{'─' * 64}\n")
            f.write(f"│  ZAMAN      : {ts}\n")
            f.write(f"│  ODA        : #{room}\n")
            f.write(f"│  ÖNCELİK    : [{priority.upper()}]\n")
            f.write(f"│  GÖNDEREN   : {sender}\n")
            f.write(f"│  DÜZ METİN  : {plain}\n")
            f.write(f"│  ŞİFRELİ    : {preview}\n")
            f.write(f"│  BÜTÜNLÜK   : {integrity}\n")
            f.write(f"└{'─' * 64}\n\n")


# ─────────────────────────────────────────────────────────────────────────────
# DESIGN TOKENS
# ─────────────────────────────────────────────────────────────────────────────
T = {
    "bg0":       "#090b10",
    "bg1":       "#0f1219",
    "bg2":       "#161b26",
    "bg3":       "#1e2535",
    "border":    "#252d42",
    "accent":    "#3b82f6",
    "accent2":   "#8b5cf6",
    "accent_h":  "#2563eb",
    "success":   "#10b981",
    "warn":      "#f59e0b",
    "danger":    "#ef4444",
    "txt0":      "#f1f5f9",
    "txt1":      "#94a3b8",
    "txt2":      "#475569",
    "font_mono": "Courier New",
    "font_ui":   "Courier New",
}

EMOJIS = [
    "😀","😂","😊","😍","🤔","😅","😎","🥳","😢","😡",
    "👍","👎","❤️","🔥","✅","❌","⚠️","🔒","🔓","🛡️",
    "💻","📡","🌐","📨","🔑","⚡","🚀","💬","📞","🤝",
]

# ─────────────────────────────────────────────────────────────────────────────
# MESSAGE PRIORITY  (T'den sonra tanımlanmalı)
# ─────────────────────────────────────────────────────────────────────────────
class Priority:
    NORMAL = "normal"
    URGENT = "acil"
    SECRET = "gizli"
    ORDER  = [NORMAL, URGENT, SECRET]

    # (görüntü etiketi, düğme rengi, textbox tag adı)
    META = {
        NORMAL: ("⬜ NORMAL", T["txt2"],   "prio_normal"),
        URGENT: ("🟡 ACİL",   T["warn"],   "prio_acil"),
        SECRET: ("🔴 GİZLİ",  T["danger"], "prio_gizli"),
    }

    @classmethod
    def next(cls, current: str) -> str:
        idx = cls.ORDER.index(current) if current in cls.ORDER else 0
        return cls.ORDER[(idx + 1) % len(cls.ORDER)]


# ─────────────────────────────────────────────────────────────────────────────
# ROOM DATACLASS  +  ROOM MANAGER
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Room:
    name:          str
    password:      str
    icon:          str
    desc:          str
    is_predefined: bool
    crypto:        CryptoManager
    # (sender, message, is_self, priority)  — oda değiştirilince yeniden yüklenir
    messages: List[Tuple] = field(default_factory=list)
    unread:   int = 0


class RoomManager:
    def __init__(self) -> None:
        self.rooms:   dict = {}          # name → Room
        self._active: Optional[str] = None

    # ── Join / Create ─────────────────────────────────────────────────────────
    def join(self, password: str,
             custom_name: str = "") -> Tuple[bool, Optional[Room], str]:
        """
        Odaya katıl veya oluştur.
        Dönüş: (başarı, Room | None, hata_mesajı)
        """
        if password in ROOM_REGISTRY:
            info          = ROOM_REGISTRY[password]
            name          = info["name"]
            icon          = info["icon"]
            desc          = info["desc"]
            is_predefined = True
        elif custom_name.strip():
            raw_name = custom_name.strip().lower()
            name     = raw_name.replace(" ", "-")
            icon     = "🔐"
            desc     = "Özel Şifreli Kanal"
            is_predefined = False
        else:
            return False, None, \
                "Bilinmeyen şifre. Özel oda için bir isim girin."

        # Zaten katılmışsa → sadece aktif yap
        if name in self.rooms:
            self._active = name
            return True, self.rooms[name], ""

        room = Room(
            name=name,
            password=password,
            icon=icon,
            desc=desc,
            is_predefined=is_predefined,
            crypto=CryptoManager(password),
        )
        self.rooms[name] = room
        self._active = name
        return True, room, ""

    # ── Active room ────────────────────────────────────────────────────────────
    def set_active(self, name: str) -> None:
        if name in self.rooms:
            self._active = name
            self.rooms[name].unread = 0

    @property
    def active_room(self) -> Optional[Room]:
        if self._active and self._active in self.rooms:
            return self.rooms[self._active]
        return None

    # ── Decrypt incoming — tüm oda crypto'larını dener ────────────────────────
    def decrypt_incoming(self, raw: str) -> Optional[Tuple[Room, dict]]:
        for room in self.rooms.values():
            data = room.crypto.decrypt(raw)
            if data is not None:
                return room, data
        return None


# ─────────────────────────────────────────────────────────────────────────────
# REUSABLE WIDGETS
# ─────────────────────────────────────────────────────────────────────────────
class StatusDot(ctk.CTkFrame):
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
    def __init__(self, parent, on_pick: Callable):
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
            ctk.CTkButton(
                grid, text=e, width=28, height=28,
                font=("Segoe UI Emoji", 15),
                fg_color="transparent", hover_color=T["bg3"],
                command=lambda em=e: self._pick(em),
            ).grid(row=i // cols, column=i % cols, padx=1, pady=1)

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
        ctk.CTkLabel(self, text="⚙  Bağlantı Ayarları",
                     font=(T["font_mono"], 16, "bold"),
                     text_color=T["txt0"]).pack(pady=(24, 16))

        for label, attr, default in [
            ("ESP32 IP Adresi",                "esp32_host",      self.config.esp32_host),
            ("Port",                           "esp32_port",      str(self.config.esp32_port)),
            ("Yeniden Bağlanma Gecikmesi (sn)","reconnect_delay", str(self.config.reconnect_delay)),
        ]:
            ctk.CTkLabel(self, text=label, font=(T["font_mono"], 11),
                         text_color=T["txt1"]).pack(**pad, anchor="w")
            entry = ctk.CTkEntry(self, width=372, height=38, font=(T["font_mono"], 13),
                                  fg_color=T["bg3"], border_color=T["border"],
                                  text_color=T["txt0"])
            entry.insert(0, default)
            entry.pack(**pad)
            setattr(self, f"_{attr}_entry", entry)

        ctk.CTkButton(self, text="Kaydet & Kapat", width=372, height=42,
                      fg_color=T["accent"], hover_color=T["accent_h"],
                      font=(T["font_mono"], 13, "bold"),
                      command=self._save).pack(pady=20)

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
    def __init__(self, parent, on_login: Callable):
        super().__init__(parent, fg_color="transparent")
        self.on_login = on_login
        self._build()

    def _build(self):
        card = ctk.CTkFrame(self, fg_color=T["bg2"], corner_radius=14,
                             border_width=1, border_color=T["border"],
                             width=380, height=500)
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.pack_propagate(False)

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

        self._user_e = ctk.CTkEntry(card, placeholder_text="Kullanıcı Adı",
                                     width=310, height=46, font=(T["font_mono"], 13),
                                     fg_color=T["bg3"], border_color=T["border"],
                                     text_color=T["txt0"])
        self._user_e.pack(pady=5)

        self._pass_e = ctk.CTkEntry(card,
                                     placeholder_text="Güvenlik Anahtarı (min. 6 karakter)",
                                     show="*", width=310, height=46,
                                     font=(T["font_mono"], 13),
                                     fg_color=T["bg3"], border_color=T["border"],
                                     text_color=T["txt0"])
        self._pass_e.pack(pady=5)

        self._err_lbl = ctk.CTkLabel(card, text="", font=(T["font_mono"], 11),
                                      text_color=T["danger"])
        self._err_lbl.pack(pady=2)

        ctk.CTkButton(card, text="BAĞLAN", width=310, height=46,
                      font=(T["font_mono"], 14, "bold"),
                      fg_color=T["accent"], hover_color=T["accent_h"],
                      corner_radius=8, command=self._attempt).pack(pady=12)

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
# ROOM JOIN DIALOG  — 2 aşamalı katılım
# Aşama 1: Şifre gir
#   → ROOM_REGISTRY'de varsa: doğrudan katıl
#   → Yoksa Aşama 2'ye geç
# Aşama 2: Özel oda adı gir → yeni oda oluştur
# ─────────────────────────────────────────────────────────────────────────────
class RoomJoinDialog(ctk.CTkToplevel):
    def __init__(self, parent, on_join: Callable):
        super().__init__(parent)
        self.on_join   = on_join
        self._phase    = 1
        self._password = ""

        self.title("Kanala Katıl")
        self.geometry("400x420")
        self.resizable(False, False)
        self.configure(fg_color=T["bg2"])
        self.attributes("-topmost", True)
        self._build()
        self.after(150, self._entry.focus)   # Açılınca odaklan

    def _build(self):
        wrap = ctk.CTkFrame(self, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=24, pady=20)

        # İkon
        ctk.CTkLabel(wrap, text="📡", font=("Segoe UI Emoji", 38)).pack(pady=(0, 6))

        # Başlık / alt başlık (aşamaya göre değişir)
        self._title_lbl = ctk.CTkLabel(wrap, text="Kanal Şifresi",
                                        font=(T["font_mono"], 16, "bold"),
                                        text_color=T["txt0"])
        self._title_lbl.pack()
        self._sub_lbl = ctk.CTkLabel(wrap,
                                      text="Kanala ait şifreyi girin",
                                      font=(T["font_mono"], 11),
                                      text_color=T["txt1"])
        self._sub_lbl.pack(pady=(2, 14))

        # ── Kayıtlı kanallar bilgi kutusu ─────────────────────────────────────
        reg_box = ctk.CTkFrame(wrap, fg_color=T["bg3"], corner_radius=8)
        reg_box.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(reg_box, text="  Kayıtlı Kanallar:",
                     font=(T["font_mono"], 9, "bold"),
                     text_color=T["txt2"]).pack(anchor="w", padx=10, pady=(8, 2))

        for pw, info in ROOM_REGISTRY.items():
            row = ctk.CTkFrame(reg_box, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=1)
            ctk.CTkLabel(row,
                         text=f"  {info['icon']}  #{info['name']}",
                         font=(T["font_mono"], 10),
                         text_color=T["txt0"]).pack(side="left")
            ctk.CTkLabel(row,
                         text=f"→  {pw}",
                         font=(T["font_mono"], 10),
                         text_color=T["accent"]).pack(side="right")

        ctk.CTkFrame(reg_box, fg_color="transparent", height=6).pack()

        # ── Giriş alanı ───────────────────────────────────────────────────────
        self._entry = ctk.CTkEntry(
            wrap,
            placeholder_text="Şifre girin (örn: 000001)",
            width=352, height=42, show="*",
            font=(T["font_mono"], 13),
            fg_color=T["bg3"], border_color=T["border"],
            text_color=T["txt0"],
        )
        self._entry.pack(pady=(0, 6))
        self._entry.bind("<Return>", lambda _: self._next())

        self._err_lbl = ctk.CTkLabel(wrap, text="",
                                      font=(T["font_mono"], 11),
                                      text_color=T["danger"])
        self._err_lbl.pack(pady=(0, 4))

        self._btn = ctk.CTkButton(wrap, text="Devam  →", width=352, height=42,
                                   font=(T["font_mono"], 13, "bold"),
                                   fg_color=T["accent"], hover_color=T["accent_h"],
                                   command=self._next)
        self._btn.pack()

    # ── Aşama geçişi ──────────────────────────────────────────────────────────
    def _next(self):
        val = self._entry.get().strip()

        if self._phase == 1:
            # ── Aşama 1: şifre doğrulama ──────────────────────────────────────
            if not val:
                self._err_lbl.configure(text="⚠  Şifre boş olamaz.")
                return

            self._password = val

            if val in ROOM_REGISTRY:
                # Bilinen oda → direkt katıl
                self.on_join(self._password, "")
                self.destroy()
            else:
                # Bilinmeyen şifre → özel oda adı iste
                self._phase = 2
                self._title_lbl.configure(text="Özel Oda Adı")
                self._sub_lbl.configure(
                    text=f"Şifre: {self._password[:3]}···  |  Yeni odanın adını belirleyin")
                self._entry.configure(show="",
                                       placeholder_text="Oda adı (örn: taktik-kanal)")
                self._entry.delete(0, "end")
                self._btn.configure(text="Oda Oluştur  ✓")
                self._err_lbl.configure(text="")
                self._entry.focus()

        elif self._phase == 2:
            # ── Aşama 2: oda adı doğrulama ────────────────────────────────────
            name = val
            if len(name) < 2:
                self._err_lbl.configure(text="⚠  Oda adı en az 2 karakter olmalı.")
                return
            forbidden = set(r'/\:*?"<>|')
            if any(c in name for c in forbidden):
                self._err_lbl.configure(text="⚠  Geçersiz karakter içeriyor.")
                return
            self.on_join(self._password, name)
            self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# ROOM SIDEBAR  — sol panel
# ─────────────────────────────────────────────────────────────────────────────
class RoomSidebar(ctk.CTkFrame):
    """
    Sol panel: katılınan odaları listeler, aktif odayı vurgular,
    okunmamış mesajları badge ile gösterir.
    """

    def __init__(self, parent, room_manager: RoomManager,
                 on_select: Callable, on_join_request: Callable):
        super().__init__(parent, fg_color=T["bg1"], width=200, corner_radius=0)
        self.pack_propagate(False)

        self.room_manager    = room_manager
        self.on_select       = on_select
        self.on_join_request = on_join_request
        self._room_btns: dict = {}  # room_name → CTkButton

        self._build()

    def _build(self):
        # ── Sidebar header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=T["bg2"], height=52, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="📡  KANALLAR",
                     font=(T["font_mono"], 11, "bold"),
                     text_color=T["txt0"]).pack(side="left", padx=12)

        # ── Kaydırılabilir oda listesi ─────────────────────────────────────────
        self._list = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                             corner_radius=0)
        self._list.pack(fill="both", expand=True)

        # Standart oda bölümü başlığı
        self._sep_std = ctk.CTkLabel(
            self._list, text="  ─── STANDART ───",
            font=(T["font_mono"], 9), text_color=T["txt2"])
        self._sep_std.pack(anchor="w", padx=6, pady=(10, 2))

        # Özel oda bölümü başlığı (ilk özel oda eklenince gösterilir)
        self._sep_custom = ctk.CTkLabel(
            self._list, text="  ─── ÖZEL ───",
            font=(T["font_mono"], 9), text_color=T["txt2"])

        # ── Alt kısım: oda ekleme butonu ──────────────────────────────────────
        bottom = ctk.CTkFrame(self, fg_color=T["bg2"], height=58, corner_radius=0)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)
        ctk.CTkButton(
            bottom,
            text="＋  ODA KATIL / EKLE",
            width=180, height=36,
            font=(T["font_mono"], 10, "bold"),
            fg_color=T["bg3"], hover_color=T["accent"],
            border_color=T["border"], border_width=1,
            command=self.on_join_request,
        ).pack(pady=11, padx=10)

    # ── Sidebar yenileme ──────────────────────────────────────────────────────
    def refresh(self):
        """Oda butonlarını room_manager'dan yeniden oluştur."""
        for btn in self._room_btns.values():
            btn.destroy()
        self._room_btns.clear()

        has_custom = any(not r.is_predefined for r in self.room_manager.rooms.values())

        if has_custom:
            self._sep_custom.pack(anchor="w", padx=6, pady=(10, 2))
        else:
            self._sep_custom.pack_forget()

        for room in self.room_manager.rooms.values():
            self._add_btn(room)

        active = self.room_manager.active_room
        if active:
            self._highlight(active.name)

    def _add_btn(self, room: Room):
        label = f"  {room.icon}  #{room.name}"
        btn = ctk.CTkButton(
            self._list,
            text=label,
            anchor="w",
            height=38, corner_radius=6,
            font=(T["font_mono"], 11),
            fg_color="transparent",
            hover_color=T["bg3"],
            text_color=T["txt1"],
            command=lambda n=room.name: self.on_select(n),
        )
        btn.pack(fill="x", padx=6, pady=2)
        self._room_btns[room.name] = btn

    def set_active(self, name: str):
        """Aktif odayı vurgula ve unread sıfırla."""
        room = self.room_manager.rooms.get(name)
        if room:
            room.unread = 0
        self._highlight(name)
        self._update_badge(name)

    def _highlight(self, active_name: str):
        for name, btn in self._room_btns.items():
            if name == active_name:
                btn.configure(fg_color=T["accent"], text_color=T["txt0"])
            else:
                btn.configure(fg_color="transparent", text_color=T["txt1"])

    # ── Okunmamış badge ───────────────────────────────────────────────────────
    def mark_unread(self, room_name: str):
        room = self.room_manager.rooms.get(room_name)
        if room:
            room.unread += 1
            self._update_badge(room_name)

    def _update_badge(self, room_name: str):
        room = self.room_manager.rooms.get(room_name)
        btn  = self._room_btns.get(room_name)
        if not room or not btn:
            return
        base = f"  {room.icon}  #{room.name}"
        if room.unread > 0:
            btn.configure(text=f"{base}  ({room.unread})",
                          text_color=T["warn"])
        else:
            btn.configure(text=base)


# ─────────────────────────────────────────────────────────────────────────────
# CHAT FRAME  — çok odalı + öncelik sistemi
# ─────────────────────────────────────────────────────────────────────────────
class ChatFrame(ctk.CTkFrame):
    def __init__(self, parent, user_id: str, room_manager: RoomManager,
                 ws: WebSocketManager, logger_: ChatLogger,
                 config: AppConfig, on_settings: Callable,
                 session_manager=None, connection_quality=None):
        super().__init__(parent, fg_color=T["bg0"])

        self.user_id          = user_id
        self.room_manager     = room_manager
        self.ws               = ws
        self.chat_logger      = logger_
        self.config           = config
        self.on_settings      = on_settings
        self._session_manager = session_manager
        self._connection_quality = connection_quality or ConnectionQuality()
        self._msg_count       = 0
        self._current_priority = Priority.NORMAL
        self._typing_indicator = None
        self._sidebar_ref: Optional[RoomSidebar] = None  # SecureBridgeApp tarafından set edilir

        self._build_header()
        self._build_statusbar()
        self._build_textarea()
        self._build_inputbar()
        self._wire_ws()
        self._set_input_enabled(False)   # Oda seçilene kadar giriş kapalı

    def set_sidebar(self, sidebar: RoomSidebar):
        self._sidebar_ref = sidebar

    # ── Header ───────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=T["bg2"], height=52, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        self._room_lbl = ctk.CTkLabel(hdr, text="🔒 SecureBridge",
                                       font=(T["font_mono"], 14, "bold"),
                                       text_color=T["txt0"])
        self._room_lbl.pack(side="left", padx=16)

        # Sağ kontroller
        for text, cmd in [
            ("📊", self._show_sessions),
            ("⚙",  self.on_settings),
            ("🗑",  self._clear),
        ]:
            ctk.CTkButton(hdr, text=text, width=34, height=34,
                          font=(T["font_mono"], 15),
                          fg_color="transparent", hover_color=T["bg3"],
                          command=cmd).pack(side="right", padx=4)

        badge = ctk.CTkFrame(hdr, fg_color=T["accent"], corner_radius=5)
        badge.pack(side="right", padx=8)
        ctk.CTkLabel(badge, text=f"  {self.user_id}  ",
                     font=(T["font_mono"], 11, "bold"),
                     text_color=T["txt0"]).pack(padx=4, pady=2)

        ctk.CTkButton(hdr, text="☢ PANIC", width=70, height=30,
                      fg_color="#991b1b", hover_color="#ef4444",
                      font=(T["font_mono"], 11, "bold"),
                      command=self._emergency_zeroize).pack(side="right", padx=10)

    # ── Status bar ───────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=T["bg1"], height=26, corner_radius=0)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self._status = StatusDot(bar)
        self._status.pack(side="left", padx=12, pady=3)
        self._status.connecting()

        sig = ctk.CTkFrame(bar, fg_color="transparent")
        sig.pack(side="left", padx=8)
        self._signal_lbl = ctk.CTkLabel(sig, text="📶 ____",
                                         font=(T["font_mono"], 10),
                                         text_color=T["txt2"])
        self._signal_lbl.pack(side="left")
        self._ping_lbl = ctk.CTkLabel(sig, text="--ms",
                                       font=(T["font_mono"], 9),
                                       text_color=T["txt2"])
        self._ping_lbl.pack(side="left", padx=4)

        self._typing_lbl = ctk.CTkLabel(bar, text="",
                                         font=(T["font_mono"], 10),
                                         text_color=T["accent"])
        self._typing_lbl.pack(side="left", padx=8)
        self._typing_indicator = TypingIndicator(self._typing_lbl)

        self._count_lbl = ctk.CTkLabel(bar, text="",
                                        font=(T["font_mono"], 10),
                                        text_color=T["txt2"])
        self._count_lbl.pack(side="right", padx=12)

    # ── Chat area ────────────────────────────────────────────────────────────
    def _build_textarea(self):
        # Boş durum ekranı (oda seçilmeden önce)
        self._empty_frame = ctk.CTkFrame(self, fg_color=T["bg0"])
        self._empty_frame.pack(fill="both", expand=True)

        ctk.CTkLabel(self._empty_frame, text="📡",
                     font=("Segoe UI Emoji", 52)).pack(expand=True, pady=(80, 8))
        ctk.CTkLabel(self._empty_frame, text="Bir kanala katılın",
                     font=(T["font_mono"], 18, "bold"),
                     text_color=T["txt0"]).pack()
        ctk.CTkLabel(self._empty_frame,
                     text="Sol panelden mevcut bir kanala katılın\n"
                          "veya yeni bir şifreli kanal oluşturun.",
                     font=(T["font_mono"], 12), text_color=T["txt2"],
                     justify="center").pack(pady=8)

        # Gerçek sohbet alanı (oda seçilince görünür)
        self._chat_outer = ctk.CTkFrame(self, fg_color=T["bg0"])

        self._chat = ctk.CTkTextbox(
            self._chat_outer,
            font=(T["font_mono"], 13),
            fg_color=T["bg0"], text_color=T["txt0"],
            border_width=0, wrap="word", spacing3=4,
        )
        self._chat.pack(fill="both", expand=True, padx=10, pady=(6, 2))
        self._chat.configure(state="disabled")

        tb = self._chat._textbox
        tb.tag_configure("ts",          foreground=T["txt2"])
        tb.tag_configure("me",          foreground=T["accent"])
        tb.tag_configure("other",       foreground=T["accent2"])
        tb.tag_configure("system",      foreground=T["warn"])
        tb.tag_configure("danger",      foreground=T["danger"])
        tb.tag_configure("body",        foreground=T["txt0"])
        # Öncelik etiketleri
        tb.tag_configure("prio_normal", foreground=T["txt2"])
        tb.tag_configure("prio_acil",   foreground=T["warn"],   background="#261c00")
        tb.tag_configure("prio_gizli",  foreground=T["danger"], background="#220000")

    # ── Input bar ────────────────────────────────────────────────────────────
    def _build_inputbar(self):
        bar = ctk.CTkFrame(self, fg_color=T["bg2"], height=66, corner_radius=0)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill="x", padx=10, pady=10)

        # Emoji butonu
        ctk.CTkButton(inner, text="😊", width=42, height=42,
                      font=("Segoe UI Emoji", 17),
                      fg_color=T["bg3"], hover_color=T["border"],
                      corner_radius=8, command=self._open_emoji).pack(side="left", padx=(0, 4))

        # ── Öncelik seçici butonu (tıkla → döngüsel) ─────────────────────────
        lbl, col, _ = Priority.META[Priority.NORMAL]
        self._prio_btn = ctk.CTkButton(
            inner,
            text=lbl, width=86, height=42,
            font=(T["font_mono"], 9, "bold"),
            fg_color=T["bg3"], hover_color=T["border"],
            text_color=col, corner_radius=8,
            command=self._cycle_priority,
        )
        self._prio_btn.pack(side="left", padx=(0, 4))

        # Mesaj giriş alanı
        self._entry = ctk.CTkEntry(
            inner,
            placeholder_text="Önce bir kanala katılın  →",
            height=42, font=(T["font_mono"], 13),
            fg_color=T["bg3"], border_color=T["border"],
            text_color=T["txt0"], corner_radius=8,
        )
        self._entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._entry.bind("<KeyRelease>", self._on_key)
        self._entry.bind("<Return>",     lambda _: self._send())

        self._char_lbl = ctk.CTkLabel(inner, text="0", width=30,
                                       font=(T["font_mono"], 10),
                                       text_color=T["txt2"])
        self._char_lbl.pack(side="left", padx=(0, 4))

        self._send_btn = ctk.CTkButton(
            inner, text="↑", width=42, height=42,
            font=(T["font_mono"], 17, "bold"),
            fg_color=T["accent"], hover_color=T["accent_h"],
            corner_radius=8, command=self._send,
        )
        self._send_btn.pack(side="right")

    # ── Input enable/disable ─────────────────────────────────────────────────
    def _set_input_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self._entry.configure(state=state)
        self._send_btn.configure(state=state)
        self._prio_btn.configure(state=state)
        if enabled:
            self._entry.configure(placeholder_text="Mesajınızı yazın…  (Enter = gönder)")
        else:
            self._entry.configure(placeholder_text="Önce bir kanala katılın  →")

    # ── Priority cycle ────────────────────────────────────────────────────────
    def _cycle_priority(self):
        self._current_priority = Priority.next(self._current_priority)
        lbl, col, _ = Priority.META[self._current_priority]
        self._prio_btn.configure(text=lbl, text_color=col)

    # ── Room switch ───────────────────────────────────────────────────────────
    def switch_room(self, room_name: str):
        """Aktif odayı değiştir, mesaj geçmişini yeniden yükle."""
        self.room_manager.set_active(room_name)
        room = self.room_manager.active_room
        if not room:
            return

        # Boş durumu gizle, sohbet alanını göster
        self._empty_frame.pack_forget()
        self._chat_outer.pack(fill="both", expand=True)

        # Header'ı güncelle
        self._room_lbl.configure(text=f"{room.icon}  #{room.name}")

        # Sohbeti temizle ve bu odanın mesajlarını yükle
        self._chat.configure(state="normal")
        self._chat.delete("1.0", "end")
        self._chat.configure(state="disabled")
        self._msg_count = 0

        for sender, msg, is_self, priority in room.messages:
            self._append(sender, msg, is_self, priority, _save=False)

        self._sys(f"📡  #{room.name}  ·  {room.desc}  ·  AES-256 aktif ✓")
        self._count_lbl.configure(text=f"{self._msg_count} mesaj")
        self._set_input_enabled(True)
        self._entry.focus()

    # ── WebSocket wiring ─────────────────────────────────────────────────────
    def _wire_ws(self):
        self.ws.on_connecting   = lambda: self.after(0, self._status.connecting)
        self.ws.on_connected    = lambda: self.after(0, self._on_ws_connected)
        self.ws.on_disconnected = lambda: self.after(0, self._status.disconnected)
        self.ws.on_message      = self._on_incoming
        self.ws.on_ping_update  = lambda ms: self.after(0, lambda: self._update_quality(ms))

    def _on_ws_connected(self):
        self._status.connected(self.ws.config.uri)

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
        msg  = self._entry.get().strip()
        room = self.room_manager.active_room

        if not msg:
            return
        if room is None:
            return   # Giriş zaten disable, bu durum oluşmamalı
        if not self.ws.is_connected:
            self._sys("⚠  Bağlantı yok. ESP32 Wi-Fi ağına bağlı olduğunuzdan emin olun.",
                      danger=True)
            return

        priority  = self._current_priority
        encrypted = room.crypto.encrypt(self.user_id, msg,
                                        room=room.name, priority=priority)
        if self.ws.send(encrypted):
            self.chat_logger.log(f"Siz ({self.user_id})", msg, encrypted,
                                 room=room.name, priority=priority, verified=True)
            self._append("Siz", msg, is_self=True, priority=priority)
            self._entry.delete(0, "end")
            self._char_lbl.configure(text="0", text_color=T["txt2"])
        else:
            self._sys("⚠  Mesaj gönderilemedi.", danger=True)

    # ── Incoming messages ────────────────────────────────────────────────────
    def _on_incoming(self, raw: str):
        # Sistem JSON mesajı mı?
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and data.get("type") == "session_update":
                if self._session_manager:
                    self._session_manager.sessions = data.get("clients", {})
                return
        except Exception:
            pass

        # Tüm oda crypto'larıyla çözmeye çalış
        result = self.room_manager.decrypt_incoming(raw)
        if result is None:
            return   # Hiçbir odamızın anahtarıyla çözülemedi

        room, decoded = result

        # Kendi mesajımızın yankısını gösterme
        if decoded.get("id") == self.user_id:
            return

        sender   = decoded.get("id", "?")
        msg      = decoded.get("msg", "")
        priority = decoded.get("priority", Priority.NORMAL)

        # Oda tamponuna kaydet
        room.messages.append((sender, msg, False, priority))
        self.chat_logger.log(sender, msg, raw,
                             room=room.name, priority=priority, verified=True)

        active = self.room_manager.active_room
        if active and room.name == active.name:
            # Aktif oda → hemen göster
            self.after(0, lambda s=sender, m=msg, p=priority:
                       self._append(s, m, is_self=False, priority=p))
        else:
            # Başka oda → sidebar'da badge göster
            if self._sidebar_ref:
                self.after(0, lambda rn=room.name:
                           self._sidebar_ref.mark_unread(rn))

    # ── Display helpers ───────────────────────────────────────────────────────
    def _append(self, sender: str, message: str, is_self: bool,
                priority: str = Priority.NORMAL, _save: bool = True):
        """
        Sohbet alanına mesaj ekle.
        _save=True → aktif odanın messages listesine kaydeder
        _save=False → sadece UI'a basar (switch_room yüklemesi için)
        """
        if _save:
            room = self.room_manager.active_room
            if room:
                room.messages.append((sender, message, is_self, priority))

        self._chat.configure(state="normal")
        tb   = self._chat._textbox
        ts   = datetime.now().strftime("%H:%M")
        pfx  = "  ▶ " if is_self else "  ◀ "
        stag = "me" if is_self else "other"

        # Öncelik meta verisi
        prio_label, _, prio_tag = Priority.META.get(priority, Priority.META[Priority.NORMAL])

        tb.insert("end", f"\n{pfx}", "ts")
        tb.insert("end", sender, stag)
        tb.insert("end", f"  {ts}  ", "ts")
        tb.insert("end", f"[{prio_label}]\n", prio_tag)
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
        room = self.room_manager.active_room
        if room:
            room.messages.clear()

    def _open_emoji(self):
        EmojiPicker(self, on_pick=lambda e: (self._entry.insert("end", e),
                                              self._entry.focus()))

    # ── Sessions dialog ─────────────────────────────────────────────────────
    def _show_sessions(self):
        if self._session_manager:
            SessionDialog(self, self._session_manager)
        else:
            self._sys("Oturum yönetimi mevcut değil.")

    # ── Connection quality ───────────────────────────────────────────────────
    def _update_quality(self, ping_ms: float):
        self._connection_quality.add_ping(ping_ms)
        q      = self._connection_quality.quality
        signal = self._connection_quality.signal_strength
        avg    = int(self._connection_quality.average_ping)
        color  = (T["success"] if q in ("excellent", "good")
                  else T["warn"] if q == "fair" else T["danger"])
        self._signal_lbl.configure(text=f"📶 {signal}", text_color=color)
        self._ping_lbl.configure(text=f"{avg}ms",       text_color=color)

    # ── Panic / Zeroize ───────────────────────────────────────────────────────
    def _emergency_zeroize(self):
        """Askeri standartta tüm oda anahtarlarını ve logları yok et."""
        for room in self.room_manager.rooms.values():
            room.crypto.zeroize()
            room.messages.clear()

        for f in ["securebridge.log", self.chat_logger.log_file]:
            try:
                if os.path.exists(f):
                    size = os.path.getsize(f)
                    with open(f, "ba+", buffering=0) as fh:
                        fh.write(os.urandom(size))
                    os.remove(f)
            except Exception:
                pass

        logger.info("KRİPTOGRAFİK İMHA: Tüm oda anahtarları ve loglar yok edildi.")
        self.master.destroy()
        sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# USER STATUS
# ─────────────────────────────────────────────────────────────────────────────
class UserStatus:
    ONLINE  = "online"
    OFFLINE = "offline"
    AWAY    = "away"
    DND     = "dnd"

    @staticmethod
    def to_emoji(status: str) -> str:
        return {"online": "🟢", "offline": "⚫",
                "away": "🟡", "dnd": "🔴"}.get(status, "⚫")

    @staticmethod
    def to_text(status: str) -> str:
        return {"online": "Çevrimiçi", "offline": "Çevrimdışı",
                "away": "Uzakta",      "dnd": "Rahatsız Etmeyin"}.get(status, "Bilinmiyor")


# ─────────────────────────────────────────────────────────────────────────────
# TYPING INDICATOR
# ─────────────────────────────────────────────────────────────────────────────
class TypingIndicator:
    _STATES = ["", ".", "..", "..."]

    def __init__(self, label: ctk.CTkLabel):
        self._label    = label
        self._index    = 0
        self._after_id = None
        self._active   = False
        self._username = ""

    def start(self, username: str):
        self._username = username
        self._active   = True
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
        self._label.configure(
            text=f"  ✏️ {self._username} yazıyor{self._STATES[self._index]}")
        self._after_id = self._label.after(400, self._animate)


# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION QUALITY
# ─────────────────────────────────────────────────────────────────────────────
class ConnectionQuality:
    def __init__(self):
        self._pings: List[float] = []

    def add_ping(self, ms: float):
        self._pings.append(ms)
        if len(self._pings) > 10:
            self._pings.pop(0)

    @property
    def average_ping(self) -> float:
        return sum(self._pings) / len(self._pings) if self._pings else 0

    @property
    def quality(self) -> str:
        avg = self.average_ping
        if avg == 0:  return "unknown"
        if avg < 50:  return "excellent"
        if avg < 100: return "good"
        if avg < 200: return "fair"
        return "poor"

    @property
    def signal_strength(self) -> str:
        return {"excellent": "▂▄▆█", "good": "▂▄▆_",
                "fair": "▂▄__",      "poor": "▂___",
                "unknown": "____"}.get(self.quality, "____")


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM TRAY
# ─────────────────────────────────────────────────────────────────────────────
class SystemTray:
    def __init__(self, app: ctk.CTk, on_show: Callable, on_quit: Callable):
        self._app     = app
        self._on_show = on_show
        self._on_quit = on_quit
        self._win     = None

    def minimize_to_tray(self):
        self._app.withdraw()
        self._create_menu()

    def restore_from_tray(self):
        if self._win:
            self._win.destroy()
            self._win = None
        self._app.deiconify()
        self._app.lift()

    def _create_menu(self):
        self._win = ctk.CTkToplevel(self._app)
        self._win.overrideredirect(True)
        self._win.geometry(f"200x80+{self._app.winfo_x()}+{self._app.winfo_y()}")
        self._win.configure(fg_color=T["bg2"])
        ctk.CTkLabel(self._win, text="🔒 SecureBridge",
                     font=(T["font_mono"], 12, "bold"),
                     text_color=T["txt0"]).pack(pady=10)
        f = ctk.CTkFrame(self._win, fg_color="transparent")
        f.pack(pady=5)
        ctk.CTkButton(f, text="Göster", width=70, height=28,
                      fg_color=T["accent"], hover_color=T["accent_h"],
                      command=self.restore_from_tray).pack(side="left", padx=5)
        ctk.CTkButton(f, text="Çık", width=70, height=28,
                      fg_color=T["danger"], hover_color="#dc2626",
                      command=self._on_quit).pack(side="left", padx=5)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION MANAGER  (sessions artık dict — SessionDialog ile uyumlu)
# ─────────────────────────────────────────────────────────────────────────────
class SessionManager:
    def __init__(self):
        self.sessions: dict = {}   # session_id → info

    def get_sessions(self) -> dict:
        return self.sessions

    def add_session(self, session_id: str, username: str, ip: str = ""):
        self.sessions[session_id] = {
            "username":     username,
            "ip":           ip,
            "connected_at": datetime.now().strftime("%H:%M:%S"),
            "status":       UserStatus.ONLINE,
        }

    def remove_session(self, session_id: str):
        self.sessions.pop(session_id, None)

    def update_status(self, session_id: str, status: str):
        if session_id in self.sessions:
            self.sessions[session_id]["status"] = status


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
        ctk.CTkLabel(self, text="📋 Aktif Oturumlar",
                     font=(T["font_mono"], 14, "bold"),
                     text_color=T["txt0"]).pack(pady=(16, 8))
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent", height=220)
        self._list_frame.pack(fill="both", expand=True, padx=16, pady=8)
        bf = ctk.CTkFrame(self, fg_color="transparent")
        bf.pack(fill="x", padx=16, pady=8)
        ctk.CTkButton(bf, text="🔄 Yenile", width=120,
                      fg_color=T["accent"], hover_color=T["accent_h"],
                      command=self._refresh).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="Kapat", width=120,
                      fg_color=T["bg3"], hover_color=T["border"],
                      command=self.destroy).pack(side="right", padx=4)

    def _refresh(self):
        for w in self._list_frame.winfo_children():
            w.destroy()
        sessions = self.session_manager.get_sessions()
        if not sessions:
            ctk.CTkLabel(self._list_frame, text="Aktif oturum yok",
                         font=(T["font_mono"], 11),
                         text_color=T["txt2"]).pack(pady=20)
            return
        for sid, info in sessions.items():
            row = ctk.CTkFrame(self._list_frame, fg_color=T["bg3"])
            row.pack(fill="x", pady=4)
            emoji = UserStatus.to_emoji(info.get("status", "offline"))
            ctk.CTkLabel(row, text=f"{emoji} {info['username']}",
                         font=(T["font_mono"], 11, "bold"),
                         text_color=T["txt0"]).pack(side="left", padx=8, pady=8)
            ctk.CTkLabel(row, text=f"Bağlanma: {info['connected_at']}",
                         font=(T["font_mono"], 9),
                         text_color=T["txt2"]).pack(side="left", padx=8)
            ctk.CTkButton(row, text="Sonlandır", width=70, height=24,
                          fg_color=T["danger"], hover_color="#dc2626",
                          font=(T["font_mono"], 9),
                          command=lambda s=sid: self._kill(s)).pack(side="right", padx=8)

    def _kill(self, sid: str):
        self.session_manager.remove_session(sid)
        self._refresh()


# ─────────────────────────────────────────────────────────────────────────────
# STATUS SELECTOR POPUP
# ─────────────────────────────────────────────────────────────────────────────
class StatusSelector(ctk.CTkToplevel):
    def __init__(self, parent, current_status: str, on_select: Callable):
        super().__init__(parent)
        self.on_select = on_select
        self.title("Durum Seç")
        self.geometry("180x160")
        self.resizable(False, False)
        self.configure(fg_color=T["bg2"])
        self.attributes("-topmost", True)

        for status, emoji, label in [
            (UserStatus.ONLINE,  "🟢", "Çevrimiçi"),
            (UserStatus.AWAY,    "🟡", "Uzakta"),
            (UserStatus.DND,     "🔴", "Rahatsız Etmeyin"),
            (UserStatus.OFFLINE, "⚫", "Çevrimdışı"),
        ]:
            ctk.CTkButton(
                self, text=f"{emoji}  {label}",
                fg_color=T["bg3"] if status != current_status else T["accent"],
                hover_color=T["border"], font=(T["font_mono"], 11),
                command=lambda s=status: self._select(s),
            ).pack(fill="x", padx=10, pady=4)

    def _select(self, status: str):
        self.on_select(status)
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION ROOT
# ─────────────────────────────────────────────────────────────────────────────
class SecureBridgeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.config = AppConfig.load()
        self.title("SecureBridge v2.0")
        self.geometry("880x780")
        self.minsize(720, 600)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=T["bg0"])

        self._room_manager       = RoomManager()
        self._session_manager    = SessionManager()
        self._connection_quality = ConnectionQuality()
        self._ws:          Optional[WebSocketManager] = None
        self._chat_log:    Optional[ChatLogger]       = None
        self._sidebar:     Optional[RoomSidebar]      = None
        self._chat_frame:  Optional[ChatFrame]        = None
        self._system_tray: Optional[SystemTray]       = None

        self._show_login()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        if self._system_tray:
            self._system_tray.minimize_to_tray()
        else:
            self.destroy()

    # ── Login ─────────────────────────────────────────────────────────────────
    def _show_login(self):
        self._login = LoginFrame(self, on_login=self._handle_login)
        self._login.pack(fill="both", expand=True)

    def _handle_login(self, username: str, password: str):
        logger.info(f"Giriş yapıldı: {username}")
        self._chat_log = ChatLogger(self.config.log_file)
        self._ws       = WebSocketManager(self.config)
        self._session_manager.add_session("local", username, "localhost")
        self._login.destroy()

        # ── Ana düzen: sidebar | ayırıcı | chat ───────────────────────────────
        main = ctk.CTkFrame(self, fg_color=T["bg0"])
        main.pack(fill="both", expand=True)

        self._sidebar = RoomSidebar(
            main,
            room_manager=self._room_manager,
            on_select=self._on_room_select,
            on_join_request=self._open_join_dialog,
        )
        self._sidebar.pack(side="left", fill="y")

        # İnce dikey ayırıcı
        ctk.CTkFrame(main, fg_color=T["border"], width=1,
                     corner_radius=0).pack(side="left", fill="y")

        self._chat_frame = ChatFrame(
            main,
            user_id=username,
            room_manager=self._room_manager,
            ws=self._ws,
            logger_=self._chat_log,
            config=self.config,
            on_settings=self._open_settings,
            session_manager=self._session_manager,
            connection_quality=self._connection_quality,
        )
        self._chat_frame.pack(side="left", fill="both", expand=True)

        # Çift yönlü referans: chat_frame → sidebar (unread badge için)
        self._chat_frame.set_sidebar(self._sidebar)

        self._ws.start()

        self._system_tray = SystemTray(
            self,
            on_show=lambda: self._system_tray.restore_from_tray(),
            on_quit=self.destroy,
        )

    # ── Room callbacks ────────────────────────────────────────────────────────
    def _on_room_select(self, room_name: str):
        self._chat_frame.switch_room(room_name)
        self._sidebar.set_active(room_name)

    def _open_join_dialog(self):
        RoomJoinDialog(self, on_join=self._handle_join)

    def _handle_join(self, password: str, custom_name: str):
        success, room, err = self._room_manager.join(password, custom_name)
        if success and room:
            self._sidebar.refresh()
            self._chat_frame.switch_room(room.name)
            self._sidebar.set_active(room.name)
        else:
            # Dialog kapandı; hatayı chat'e sys mesajı olarak yaz
            if self._chat_frame and self._room_manager.active_room:
                self._chat_frame._sys(f"⚠  Oda katılımı başarısız: {err}", danger=True)

    def _open_settings(self):
        SettingsDialog(self, self.config)


# ─────────────────────────────────────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────────────────────────────────────
def resource_path(relative: str) -> str:
    """PyInstaller EXE'lerde kaynak yolu düzelt."""
    try:
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.abspath(".")
    return os.path.join(base, relative)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SecureBridgeApp()
    app.mainloop()