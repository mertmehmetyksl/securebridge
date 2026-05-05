#!/usr/bin/env python3
"""
SecureBridge v6.4 – Panik butonu sonrası arka plan hataları giderildi.
"""

import gc, customtkinter as ctk, asyncio, threading, json, os, sys, hmac, hashlib, logging
import socket, platform, uuid, base64, websockets, psutil, matplotlib.pyplot as plt
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Optional, Callable, List, Tuple, Dict, Any
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkintermapview import TkinterMapView
import geocoder

try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, MediaStreamTrack
    from aiortc.contrib.media import MediaPlayer, MediaRecorder
    import av
    RTC_AVAILABLE = True
except ImportError:
    RTC_AVAILABLE = False

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("securebridge.log", encoding="utf-8"), logging.StreamHandler()]
)
logger = logging.getLogger("SecureBridge")

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
    theme: str = "dark"
    font_size: int = 13
    auto_scroll: bool = True
    panic_config: dict = field(default_factory=lambda: {
        "destroy_logs": True,
        "send_panic_msg": True,
        "custom_msg": "ACİL! Tüm sistem imha ediliyor.",
        "send_location": True
    })
    @property
    def uri(self): return f"ws://{self.esp32_host}:{self.esp32_port}"
    @classmethod
    def load(cls):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE,"r",encoding="utf-8") as f:
                    data = json.load(f)
                valid = {k:v for k,v in data.items() if k in cls.__dataclass_fields__}
                return cls(**valid)
            except: pass
        return cls()
    def save(self):
        with open(CONFIG_FILE,"w",encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

# ─── CryptoManager ───
class CryptoManager:
    _SALT_ENC=b"securebridge_v6_enc"; _SALT_HMAC=b"securebridge_v6_hmac"
    def __init__(self, pwd):
        self._cipher=Fernet(base64.urlsafe_b64encode(
            PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=self._SALT_ENC,iterations=100_000).derive(pwd.encode())))
        self._hmac_key=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=self._SALT_HMAC,iterations=100_000).derive(pwd.encode())
        self._seq=0; self._seen=set()
    def _sign(self, data):
        return hmac.new(self._hmac_key, data.encode(), hashlib.sha256).hexdigest()
    def encrypt(self, uid, msg, room="", priority="normal", msg_id=None):
        self._seq+=1
        if not msg_id: msg_id=str(uuid.uuid4())
        payload={"id":uid,"msg":msg,"time":datetime.now().strftime("%H:%M"),"seq":self._seq,"room":room,"priority":priority,"message_id":msg_id}
        raw=json.dumps(payload,ensure_ascii=False)
        payload["hmac"]=self._sign(raw)
        return self._cipher.encrypt(json.dumps(payload,ensure_ascii=False).encode()).decode()
    def decrypt(self, enc):
        try:
            data=json.loads(self._cipher.decrypt(enc.encode()).decode())
            h=data.pop("hmac","")
            if not hmac.compare_digest(h, self._sign(json.dumps({k:v for k,v in data.items()},ensure_ascii=False))):
                return None
            s=data.get("seq",-1)
            if s in self._seen: return None
            self._seen.add(s)
            if len(self._seen)>1000: self._seen=set(sorted(self._seen)[-500:])
            return data
        except: return None
    def zeroize(self):
        self._cipher=self._hmac_key=None; self._seen=set(); gc.collect()

# ─── WebSocket Manager ───
class ConnectionState:
    DISCONNECTED="disconnected"; CONNECTING="connecting"; CONNECTED="connected"
class WebSocketManager:
    _IGNORE={"Sunucuya bağlandınız.","Connected to server."}
    def __init__(self, config):
        self.config=config; self.websocket=None; self.loop=None; self.state=ConnectionState.DISCONNECTED
        self.on_message=self.on_connected=self.on_disconnected=self.on_connecting=self.on_ping_update=None
        self._user_id=None
    def start(self):
        threading.Thread(target=self._run_loop, daemon=True).start()
    def _run_loop(self):
        if sys.platform=="win32": asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self.loop=asyncio.new_event_loop(); asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect_loop())
    async def _connect_loop(self):
        while True:
            try:
                self.state=ConnectionState.CONNECTING
                if self.on_connecting: self.on_connecting()
                async with websockets.connect(self.config.uri) as ws:
                    self.websocket=ws; self.state=ConnectionState.CONNECTED
                    if self.on_connected: self.on_connected()
                    while self.state==ConnectionState.CONNECTED:
                        try:
                            start=self.loop.time(); await (await ws.ping())
                            if self.on_ping_update: self.on_ping_update((self.loop.time()-start)*1000)
                        except: pass
                        try:
                            raw=await asyncio.wait_for(ws.recv(), timeout=2.0)
                            if raw not in self._IGNORE and self.on_message: self.on_message(raw)
                        except asyncio.TimeoutError: continue
            except Exception as e: logger.error(f"Bağlantı hatası: {e}")
            finally:
                self.state=ConnectionState.DISCONNECTED
                if self.on_disconnected: self.on_disconnected()
            await asyncio.sleep(self.config.reconnect_delay)
    def send(self, data):
        if self.loop and self.websocket and self.state==ConnectionState.CONNECTED:
            asyncio.run_coroutine_threadsafe(self.websocket.send(data), self.loop)
            return True
        return False
    @property
    def is_connected(self): return self.state==ConnectionState.CONNECTED

# ─── ChatLogger ───
class ChatLogger:
    def __init__(self, log_file): self.log = log_file
    def log_msg(self, sender, plain, enc, room="", priority="normal", verified=True):
        ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log,"a",encoding="utf-8") as f:
            f.write(f"┌{'─'*64}\n│ ZAMAN: {ts}\n│ ODA: #{room}\n│ ÖNCELİK: [{priority.upper()}]\n")
            f.write(f"│ GÖNDEREN: {sender}\n│ DÜZ METİN: {plain}\n│ ŞİFRELİ: {enc[:72]}...\n")
            f.write(f"│ BÜTÜNLÜK: {'✓' if verified else '✗'}\n└{'─'*64}\n\n")

# ─── Tema ───
T={"bg0":"#090b10","bg1":"#0f1219","bg2":"#161b26","bg3":"#1e2535","border":"#252d42","accent":"#3b82f6",
   "accent2":"#8b5cf6","accent_h":"#2563eb","success":"#10b981","warn":"#f59e0b","danger":"#ef4444",
   "txt0":"#f1f5f9","txt1":"#94a3b8","txt2":"#475569","font_mono":"Courier New","font_ui":"Courier New"}
EMOJIS=["😀","😂","😊","😍","🤔","😅","😎","🥳","😢","😡","👍","👎","❤️","🔥","✅","❌","⚠️","🔒","🔓","🛡️","💻","📡","🌐","📨","🔑","⚡","🚀","💬","📞","🤝"]

class Priority:
    NORMAL="normal"; URGENT="acil"; SECRET="gizli"
    ORDER=[NORMAL,URGENT,SECRET]
    META={NORMAL:("⬜ NORMAL",T["txt2"],"prio_normal"),URGENT:("🟡 ACİL",T["warn"],"prio_acil"),
          SECRET:("🔴 GİZLİ",T["danger"],"prio_gizli")}
    @classmethod
    def next(cls, cur):
        idx=cls.ORDER.index(cur) if cur in cls.ORDER else 0
        return cls.ORDER[(idx+1)%len(cls.ORDER)]

@dataclass
class Room:
    name: str; icon: str="💬"; desc: str=""; messages: List[Tuple]=field(default_factory=list); unread: int=0

class RoomManager:
    def __init__(self, master):
        self.master=master; self.rooms={}; self.cryptos={}; self._active=None
    def join(self, name):
        name=name.strip().lower()
        if not name: return False, None, "Boş oda adı"
        if name in self.rooms:
            self._active=name; return True, self.rooms[name], ""
        room=Room(name=name, icon="🔐", desc="Özel Kanal")
        self.rooms[name]=room; self.cryptos[name]=CryptoManager(self.master); self._active=name
        return True, room, ""
    def set_active(self, name):
        if name in self.rooms: self._active=name; self.rooms[name].unread=0
    @property
    def active_room(self): return self.rooms.get(self._active) if self._active else None
    def crypto_for(self, name): return self.cryptos.get(name)
    def decrypt_incoming(self, raw):
        for name,crypto in self.cryptos.items():
            data=crypto.decrypt(raw)
            if data: return self.rooms[name], data
        return None

# ─── Small Widgets ───
class StatusDot(ctk.CTkFrame):
    def __init__(self,parent,**kw):
        super().__init__(parent,fg_color="transparent",**kw)
        self._dot=ctk.CTkLabel(self,text="●",font=(T["font_mono"],13)); self._dot.pack(side="left",padx=(0,5))
        self._lbl=ctk.CTkLabel(self,font=(T["font_mono"],11),text_color=T["txt1"]); self._lbl.pack(side="left")
    def connecting(self): self._dot.configure(text_color=T["warn"]); self._lbl.configure(text="Bağlanıyor…")
    def connected(self,uri): self._dot.configure(text_color=T["success"]); self._lbl.configure(text=f"Bağlı · {uri}")
    def disconnected(self): self._dot.configure(text_color=T["danger"]); self._lbl.configure(text="Bağlantı kesildi")

class EmojiPicker(ctk.CTkToplevel):
    def __init__(self,parent,on_pick):
        super().__init__(parent); self.on_pick=on_pick; self.title("Emoji"); self.geometry("336x120")
        self.configure(fg_color=T["bg2"]); self.attributes("-topmost",True)
        grid=ctk.CTkFrame(self,fg_color="transparent"); grid.pack(padx=6,pady=6,fill="both",expand=True)
        for i,e in enumerate(EMOJIS):
            ctk.CTkButton(grid,text=e,width=28,height=28,font=("Segoe UI Emoji",15),fg_color="transparent",
                          hover_color=T["bg3"],command=lambda em=e: self._pick(em)).grid(row=i//10,column=i%10,padx=1,pady=1)
    def _pick(self,e): self.on_pick(e); self.destroy()

class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent, config, on_theme_change):
        super().__init__(parent); self.config=config; self.on_theme_change=on_theme_change
        self.title("⚙ Ayarlar"); self.geometry("500x620"); self.configure(fg_color=T["bg2"]); self.attributes("-topmost",True)
        self._build()
    def _build(self):
        pad=dict(padx=24,pady=6)
        ctk.CTkLabel(self,text="⚙ Bağlantı & Görünüm",font=(T["font_mono"],16,"bold"),text_color=T["txt0"]).pack(pady=(24,10))
        for label,attr,defval in [("ESP32 IP Adresi","esp32_host",self.config.esp32_host),("Port","esp32_port",str(self.config.esp32_port)),
                                  ("Yeniden Bağlanma Gecikmesi (sn)","reconnect_delay",str(self.config.reconnect_delay))]:
            ctk.CTkLabel(self,text=label,font=(T["font_mono"],11),text_color=T["txt1"]).pack(**pad,anchor="w")
            e=ctk.CTkEntry(self,width=452,height=38,font=(T["font_mono"],13),fg_color=T["bg3"],border_color=T["border"],text_color=T["txt0"])
            e.insert(0,defval); e.pack(**pad); setattr(self,f"_{attr}_entry",e)
        ctk.CTkLabel(self,text="Tema",font=(T["font_mono"],11),text_color=T["txt1"]).pack(**pad,anchor="w")
        self._theme_var=ctk.StringVar(value=self.config.theme)
        tf=ctk.CTkFrame(self,fg_color="transparent"); tf.pack(fill="x",padx=24,pady=4)
        for txt,val in [("Koyu","dark"),("Açık","light")]:
            ctk.CTkRadioButton(tf,text=txt,variable=self._theme_var,value=val,font=(T["font_mono"],12),fg_color=T["accent"],text_color=T["txt0"]).pack(side="left",padx=10)
        ctk.CTkLabel(self,text="Panik Butonu Ayarları",font=(T["font_mono"],12,"bold"),text_color=T["warn"]).pack(padx=24,pady=(12,4),anchor="w")
        self._panic_destroy=ctk.BooleanVar(value=self.config.panic_config.get("destroy_logs",True))
        ctk.CTkCheckBox(self,text="Logları imha et",variable=self._panic_destroy,font=(T["font_mono"],12),fg_color=T["accent"],text_color=T["txt0"]).pack(padx=24,pady=2,anchor="w")
        self._panic_send=ctk.BooleanVar(value=self.config.panic_config.get("send_panic_msg",True))
        ctk.CTkCheckBox(self,text="Panik mesajı gönder",variable=self._panic_send,font=(T["font_mono"],12),fg_color=T["accent"],text_color=T["txt0"]).pack(padx=24,pady=2,anchor="w")
        ctk.CTkLabel(self,text="Mesaj:",font=(T["font_mono"],11),text_color=T["txt1"]).pack(padx=24,anchor="w")
        self._panic_msg_entry=ctk.CTkEntry(self,width=452,height=38,font=(T["font_mono"],13),fg_color=T["bg3"],border_color=T["border"],text_color=T["txt0"])
        self._panic_msg_entry.insert(0,self.config.panic_config.get("custom_msg","ACİL!")); self._panic_msg_entry.pack(padx=24,pady=2)
        self._panic_location=ctk.BooleanVar(value=self.config.panic_config.get("send_location",True))
        ctk.CTkCheckBox(self,text="Konum gönder",variable=self._panic_location,font=(T["font_mono"],12),fg_color=T["accent"],text_color=T["txt0"]).pack(padx=24,pady=2,anchor="w")
        ctk.CTkButton(self,text="Kaydet & Kapat",width=452,height=42,fg_color=T["accent"],hover_color=T["accent_h"],font=(T["font_mono"],13,"bold"),command=self._save).pack(pady=15)
    def _save(self):
        self.config.esp32_host=self._esp32_host_entry.get().strip()
        try: self.config.esp32_port=int(self._esp32_port_entry.get().strip())
        except: pass
        try: self.config.reconnect_delay=int(self._reconnect_delay_entry.get().strip())
        except: pass
        new_theme=self._theme_var.get(); changed=self.config.theme!=new_theme; self.config.theme=new_theme
        self.config.panic_config={"destroy_logs":self._panic_destroy.get(),"send_panic_msg":self._panic_send.get(),
                                  "custom_msg":self._panic_msg_entry.get().strip(),"send_location":self._panic_location.get()}
        self.config.save()
        if changed: self.on_theme_change(new_theme)
        self.destroy()

class LoginFrame(ctk.CTkFrame):
    def __init__(self,parent,on_login):
        super().__init__(parent,fg_color="transparent"); self.on_login=on_login; self._build()
    def _build(self):
        card=ctk.CTkFrame(self,fg_color=T["bg2"],corner_radius=14,border_width=1,border_color=T["border"],width=380,height=500)
        card.place(relx=0.5,rely=0.5,anchor="center"); card.pack_propagate(False)
        icon_bg=ctk.CTkFrame(card,fg_color=T["bg3"],corner_radius=40,width=72,height=72); icon_bg.pack(pady=(36,0)); icon_bg.pack_propagate(False)
        ctk.CTkLabel(icon_bg,text="🔒",font=("Segoe UI Emoji",32)).place(relx=0.5,rely=0.5,anchor="center")
        ctk.CTkLabel(card,text="SecureBridge",font=(T["font_mono"],26,"bold"),text_color=T["txt0"]).pack(pady=(14,2))
        ctk.CTkLabel(card,text="v6.4  ·  Taktik İletişim",font=(T["font_mono"],11),text_color=T["txt1"]).pack(pady=(0,28))
        self._user=ctk.CTkEntry(card,placeholder_text="Kullanıcı Adı",width=310,height=46,font=(T["font_mono"],13),fg_color=T["bg3"],border_color=T["border"],text_color=T["txt0"]); self._user.pack(pady=5)
        self._pass=ctk.CTkEntry(card,placeholder_text="Güvenlik Anahtarı (min. 6)",show="*",width=310,height=46,font=(T["font_mono"],13),fg_color=T["bg3"],border_color=T["border"],text_color=T["txt0"]); self._pass.pack(pady=5)
        self._err=ctk.CTkLabel(card,text="",font=(T["font_mono"],11),text_color=T["danger"]); self._err.pack(pady=2)
        ctk.CTkButton(card,text="BAĞLAN",width=310,height=46,font=(T["font_mono"],14,"bold"),fg_color=T["accent"],hover_color=T["accent_h"],command=self._attempt).pack(pady=12)
        self._user.bind("<Return>",lambda _:self._pass.focus()); self._pass.bind("<Return>",lambda _:self._attempt()); self._user.focus()
    def _attempt(self):
        u=self._user.get().strip(); p=self._pass.get()
        if not u: self._err.configure(text="⚠ Kullanıcı adı boş"); return
        if len(p)<6: self._err.configure(text="⚠ Anahtar en az 6 karakter"); return
        self._err.configure(text=""); self.on_login(u,p)

class AskRoomNameDialog(ctk.CTkToplevel):
    def __init__(self,parent,on_join):
        super().__init__(parent); self.on_join=on_join; self.title("Oda Aç"); self.geometry("380x220")
        self.configure(fg_color=T["bg2"]); self.attributes("-topmost",True)
        ctk.CTkLabel(self,text="➕ Oda İsmi Girin",font=(T["font_mono"],15,"bold"),text_color=T["txt0"]).pack(pady=(20,10))
        self._entry=ctk.CTkEntry(self,placeholder_text="örn: komuta-merkezi",width=320,height=46,font=(T["font_mono"],13),fg_color=T["bg3"],border_color=T["border"],text_color=T["txt0"]); self._entry.pack(pady=5)
        self._entry.bind("<Return>",lambda _:self._join()); self._err=ctk.CTkLabel(self,text="",font=(T["font_mono"],11),text_color=T["danger"]); self._err.pack()
        ctk.CTkButton(self,text="Katıl / Oluştur",width=320,height=42,font=(T["font_mono"],13,"bold"),fg_color=T["accent"],hover_color=T["accent_h"],command=self._join).pack(pady=10)
        self.after(150,self._entry.focus)
    def _join(self):
        n=self._entry.get().strip()
        if not n: self._err.configure(text="Oda adı boş olamaz"); return
        self.on_join(n); self.destroy()

class RoomSidebar(ctk.CTkFrame):
    def __init__(self,parent,room_manager,on_select,on_join_request):
        super().__init__(parent,fg_color=T["bg1"],width=200,corner_radius=0); self.pack_propagate(False)
        self.rm=room_manager; self.on_select=on_select; self.on_join_request=on_join_request; self._btns={}
        hdr=ctk.CTkFrame(self,fg_color=T["bg2"],height=52,corner_radius=0); hdr.pack(fill="x"); hdr.pack_propagate(False)
        ctk.CTkLabel(hdr,text="📡 KANALLAR",font=(T["font_mono"],11,"bold"),text_color=T["txt0"]).pack(side="left",padx=12)
        self._list=ctk.CTkScrollableFrame(self,fg_color="transparent",corner_radius=0); self._list.pack(fill="both",expand=True)
        bottom=ctk.CTkFrame(self,fg_color=T["bg2"],height=58,corner_radius=0); bottom.pack(fill="x",side="bottom"); bottom.pack_propagate(False)
        ctk.CTkButton(bottom,text="＋ ODA EKLE",width=180,height=36,font=(T["font_mono"],10,"bold"),fg_color=T["bg3"],hover_color=T["accent"],border_color=T["border"],border_width=1,command=self.on_join_request).pack(pady=11,padx=10)
    def refresh(self):
        for b in self._btns.values(): b.destroy()
        self._btns.clear()
        for room in self.rm.rooms.values():
            btn=ctk.CTkButton(self._list,text=f"  💬  #{room.name}",anchor="w",height=38,corner_radius=6,font=(T["font_mono"],11),fg_color="transparent",hover_color=T["bg3"],text_color=T["txt1"],command=lambda n=room.name: self.on_select(n))
            btn.pack(fill="x",padx=6,pady=2); self._btns[room.name]=btn
        if self.rm.active_room: self._highlight(self.rm.active_room.name)
    def set_active(self,name):
        room=self.rm.rooms.get(name)
        if room: room.unread=0
        self._highlight(name); self._update_badge(name)
    def _highlight(self,active):
        for n,b in self._btns.items(): b.configure(fg_color=T["accent"] if n==active else "transparent", text_color=T["txt0"] if n==active else T["txt1"])
    def mark_unread(self,name):
        room=self.rm.rooms.get(name)
        if room: room.unread+=1; self._update_badge(name)
    def _update_badge(self,name):
        room=self.rm.rooms.get(name); btn=self._btns.get(name)
        if not room or not btn: return
        base=f"  💬  #{room.name}"
        if room.unread>0: btn.configure(text=f"{base} ({room.unread})", text_color=T["warn"])
        else: btn.configure(text=base)

# ─── Sağ Panel (Sekmeli) ───
class RightPanel(ctk.CTkFrame):
    def __init__(self, parent, ws):
        super().__init__(parent, fg_color=T["bg1"], width=320, corner_radius=0)
        self.pack_propagate(False)
        self.ws = ws

        tab_frame = ctk.CTkFrame(self, fg_color=T["bg2"], height=40)
        tab_frame.pack(fill="x")
        self.btn_signal = ctk.CTkButton(tab_frame, text="📶 Sinyal", width=100, height=30,
                                        font=(T["font_mono"], 10, "bold"), fg_color=T["accent"], text_color=T["txt0"],
                                        command=lambda: self.show_tab("signal"))
        self.btn_signal.pack(side="left", padx=4, pady=5)
        self.btn_perf = ctk.CTkButton(tab_frame, text="📈 Performans", width=100, height=30,
                                      font=(T["font_mono"], 10, "bold"), fg_color=T["bg3"], text_color=T["txt1"],
                                      command=lambda: self.show_tab("perf"))
        self.btn_perf.pack(side="left", padx=4, pady=5)
        self.btn_map = ctk.CTkButton(tab_frame, text="📍 Harita", width=100, height=30,
                                     font=(T["font_mono"], 10, "bold"), fg_color=T["bg3"], text_color=T["txt1"],
                                     command=lambda: self.show_tab("map"))
        self.btn_map.pack(side="left", padx=4, pady=5)

        self.content = ctk.CTkFrame(self, fg_color=T["bg1"])
        self.content.pack(fill="both", expand=True)

        self.signal_map = SignalMapFrame(self.content)
        self.perf_frame = PerformanceFrame(self.content)
        self.location_frame = LocationFrame(self.content, ws=self.ws)

        self.current_tab = None
        self.show_tab("signal")

    def show_tab(self, tab):
        for btn, t in [(self.btn_signal, "signal"), (self.btn_perf, "perf"), (self.btn_map, "map")]:
            if t == tab:
                btn.configure(fg_color=T["accent"], text_color=T["txt0"])
            else:
                btn.configure(fg_color=T["bg3"], text_color=T["txt1"])

        for w in self.content.winfo_children():
            w.pack_forget()

        if tab == "signal":
            self.signal_map.pack(fill="both", expand=True, padx=5, pady=5)
        elif tab == "perf":
            self.perf_frame.pack(fill="both", expand=True, padx=5, pady=5)
        elif tab == "map":
            self.location_frame.pack(fill="both", expand=True, padx=5, pady=5)
            ctk.CTkButton(self.content, text="Konum Paylaşımını Aç/Kapat", width=180, height=25,
                          font=(T["font_mono"], 10), fg_color=T["accent"],
                          command=self.location_frame.toggle_send).pack(pady=5)

    def stop_background_tasks(self):
        """Panik butonu için tüm zamanlayıcıları durdurur."""
        if hasattr(self, 'perf_frame'):
            self.perf_frame.stop()
        if hasattr(self, 'location_frame'):
            self.location_frame.stop()

# ─── Görüntülü Arama Yöneticisi ──────────────────────────────────────
class VideoCallManager:
    def __init__(self, ws, user_id, room_name, chat_frame_callback=None):
        self.ws = ws
        self.user_id = user_id
        self.room_name = room_name
        self.chat_callback = chat_frame_callback
        self.peers = {}
        self.local_stream = None
        self.pending = set()

    async def start_call(self):
        if RTC_AVAILABLE:
            try:
                self.local_stream = MediaPlayer('/dev/video0', format='v4l2')
            except:
                self.local_stream = MediaPlayer('default')
            self.ws.send(json.dumps({"type":"video_call_invite","room":self.room_name,"from":self.user_id}))

    def handle_invite(self, from_user):
        dialog = ctk.CTkToplevel()
        dialog.title("Görüntülü Arama")
        dialog.geometry("300x150")
        ctk.CTkLabel(dialog, text=f"{from_user} görüntülü arama başlatmak istiyor.", font=(T["font_mono"],12)).pack(pady=20)
        def accept():
            dialog.destroy()
            self._accept_call(from_user)
        def reject():
            dialog.destroy()
            self.ws.send(json.dumps({"type":"video_call_reject","from":self.user_id,"to":from_user}))
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Kabul Et", fg_color=T["success"], command=accept).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Reddet", fg_color=T["danger"], command=reject).pack(side="left", padx=10)

    def _accept_call(self, from_user):
        self.ws.send(json.dumps({"type":"video_call_accept","from":self.user_id,"to":from_user}))
        if RTC_AVAILABLE:
            pc = RTCPeerConnection()
            self.peers[from_user] = pc
            if self.local_stream:
                pc.addTrack(self.local_stream.video)
            async def create_offer():
                offer = await pc.createOffer()
                await pc.setLocalDescription(offer)
                self.ws.send(json.dumps({"type":"video_offer","to":from_user,"sdp":pc.localDescription.sdp}))
            if self.ws.loop and self.ws.loop.is_running():
                asyncio.run_coroutine_threadsafe(create_offer(), self.ws.loop)
        if self.chat_callback:
            self.chat_callback(f"📹 {from_user} ile görüntülü arama başlatıldı.")

    def handle_accept(self, from_user):
        if self.chat_callback:
            self.chat_callback(f"📹 {from_user} görüntülü aramayı kabul etti.")

    def handle_reject(self, from_user):
        if self.chat_callback:
            self.chat_callback(f"📹 {from_user} görüntülü aramayı reddetti.")

# ─── Sinyal, Performans, Harita Sınıfları (stop metotları eklendi) ──
class SignalMapFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=T["bg2"])
        self.fig, self.ax = plt.subplots(figsize=(3,2), dpi=80)
        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self._data = {}
    def update(self, sessions):
        self._data.clear()
        for c in sessions:
            name = c.get("id","?")
            rssi = c.get("rssi", -100)
            self._data[name] = rssi
        self.ax.clear()
        names = list(self._data.keys())
        vals = list(self._data.values())
        self.ax.barh(names, vals, color='skyblue')
        self.ax.set_xlabel('RSSI (dBm)')
        self.ax.set_xlim(-100, -30)
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.canvas.draw()
    def stop(self):
        plt.close(self.fig)

class PerformanceFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=T["bg2"])
        self.fig, (self.ax1, self.ax2) = plt.subplots(2,1,figsize=(4,3),dpi=80)
        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.cpu=[]; self.mem=[]; self.ping=[]
        self._running = True
        self._update()
    def add_ping(self, ms):
        self.ping.append(ms)
        if len(self.ping)>50: self.ping.pop(0)
    def _update(self):
        if not self._running:
            return
        self.cpu.append(psutil.cpu_percent())
        self.mem.append(psutil.virtual_memory().percent)
        if len(self.cpu)>50: self.cpu.pop(0)
        if len(self.mem)>50: self.mem.pop(0)
        self.ax1.clear()
        self.ax1.plot(self.cpu,label='CPU %',color='cyan')
        self.ax1.plot(self.mem,label='RAM %',color='magenta')
        self.ax1.legend(loc='upper right'); self.ax1.set_ylim(0,100)
        self.ax2.clear()
        if self.ping:
            self.ax2.plot(self.ping,label='Ping (ms)',color='yellow')
            self.ax2.legend(loc='upper right')
        self.canvas.draw()
        if self._running:
            self._after_id = self.after(1000, self._update)
    def stop(self):
        self._running = False
        if hasattr(self, '_after_id'):
            self.after_cancel(self._after_id)
        plt.close(self.fig)

class LocationFrame(ctk.CTkFrame):
    def __init__(self, parent, ws=None):
        super().__init__(parent, fg_color=T["bg2"])
        self.ws = ws
        self.map_widget = TkinterMapView(self, corner_radius=0)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(41.0082, 28.9784)
        self.map_widget.set_zoom(5)
        self._markers = {}
        self._send_enabled = False
        self._running = True
    def toggle_send(self):
        self._send_enabled = not self._send_enabled
        if self._send_enabled:
            self._update_location()
    def _update_location(self):
        if not self._running:
            return
        if self._send_enabled and self.ws and self.ws.is_connected:
            try:
                g = geocoder.ip('me')
                if g.ok:
                    lat, lng = g.latlng
                    self.ws.send(json.dumps({"type":"location_update","lat":lat,"lon":lng,"user":self.ws._user_id}))
            except Exception:
                pass
        if self._running and self._send_enabled:
            self._after_id = self.after(10000, self._update_location)
    def add_marker(self, user, lat, lng):
        if user in self._markers:
            self._markers[user].delete()
        self._markers[user] = self.map_widget.set_marker(lat, lng, text=user)
    def stop(self):
        self._running = False
        if hasattr(self, '_after_id'):
            self.after_cancel(self._after_id)
        # Haritayı temizle
        self.map_widget.destroy()

# ─── ChatFrame (Panik butonunda durdurma eklendi) ────────────────────
class ChatFrame(ctk.CTkFrame):
    def __init__(self, parent, user_id, room_manager, ws, logger_, config, on_settings, sessions, conn_quality,
                 right_panel: RightPanel):
        super().__init__(parent, fg_color=T["bg0"])
        self.user_id=user_id; self.rm=room_manager; self.ws=ws; self.logger=logger_; self.config=config
        self.on_settings=on_settings; self.sessions=sessions; self.cq=conn_quality
        self.right_panel = right_panel
        self._msg_count=0; self._current_priority=Priority.NORMAL; self._sidebar=None
        self._sys_info={"hostname":socket.gethostname(),"os":f"{platform.system()} {platform.release()}","details":f"Python {platform.python_version()}"}
        self._build_header(); self._build_statusbar(); self._build_textarea(); self._build_inputbar()
        self._wire_ws(); self._set_input_enabled(False)
        self.video_mgr = None

    def set_sidebar(self, s): self._sidebar=s
    def _build_header(self):
        hdr=ctk.CTkFrame(self,fg_color=T["bg2"],height=52,corner_radius=0); hdr.pack(fill="x"); hdr.pack_propagate(False)
        self._room_lbl=ctk.CTkLabel(hdr,text="🔒 SecureBridge",font=(T["font_mono"],14,"bold"),text_color=T["txt0"]); self._room_lbl.pack(side="left",padx=16)
        for txt,cmd in [("📊",self._show_sessions),("⚙",self.on_settings),("🗑",self._clear),("📹",self._start_video_call)]:
            ctk.CTkButton(hdr,text=txt,width=34,height=34,font=(T["font_mono"],15),fg_color="transparent",hover_color=T["bg3"],command=cmd).pack(side="right",padx=4)
        badge=ctk.CTkFrame(hdr,fg_color=T["accent"],corner_radius=5); badge.pack(side="right",padx=8)
        ctk.CTkLabel(badge,text=f"  {self.user_id}  ",font=(T["font_mono"],11,"bold"),text_color=T["txt0"]).pack(padx=4,pady=2)
        ctk.CTkButton(hdr,text="☢ PANIC",width=70,height=30,fg_color="#991b1b",hover_color="#ef4444",font=(T["font_mono"],11,"bold"),command=self._emergency_zeroize).pack(side="right",padx=10)
    def _build_statusbar(self):
        bar=ctk.CTkFrame(self,fg_color=T["bg1"],height=26,corner_radius=0); bar.pack(fill="x"); bar.pack_propagate(False)
        self._status=StatusDot(bar); self._status.pack(side="left",padx=12,pady=3); self._status.connecting()
        sig=ctk.CTkFrame(bar,fg_color="transparent"); sig.pack(side="left",padx=8)
        self._signal_lbl=ctk.CTkLabel(sig,text="📶 ____",font=(T["font_mono"],10),text_color=T["txt2"]); self._signal_lbl.pack(side="left")
        self._ping_lbl=ctk.CTkLabel(sig,text="--ms",font=(T["font_mono"],9),text_color=T["txt2"]); self._ping_lbl.pack(side="left",padx=4)
        self._count_lbl=ctk.CTkLabel(bar,text="",font=(T["font_mono"],10),text_color=T["txt2"]); self._count_lbl.pack(side="right",padx=12)
    def _build_textarea(self):
        self._empty=ctk.CTkFrame(self,fg_color=T["bg0"]); self._empty.pack(fill="both",expand=True)
        ctk.CTkLabel(self._empty,text="📡",font=("Segoe UI Emoji",52)).pack(expand=True,pady=(80,8))
        ctk.CTkLabel(self._empty,text="Bir kanala katılın",font=(T["font_mono"],18,"bold"),text_color=T["txt0"]).pack()
        ctk.CTkLabel(self._empty,text="Sol panelden yeni bir kanal ekleyin",font=(T["font_mono"],12),text_color=T["txt2"]).pack(pady=8)
        self._chat_outer=ctk.CTkFrame(self,fg_color=T["bg0"])
        self._chat=ctk.CTkTextbox(self._chat_outer,font=(T["font_mono"],self.config.font_size),fg_color=T["bg0"],text_color=T["txt0"],border_width=0,wrap="word")
        self._chat.pack(fill="both",expand=True,padx=10,pady=(6,2)); self._chat.configure(state="disabled")
        tb=self._chat._textbox
        for tag,fg,bg in [("ts",T["txt2"],None),("me",T["accent"],None),("other",T["accent2"],None),("system",T["warn"],None),
                          ("danger",T["danger"],None),("body",T["txt0"],None),("prio_normal",T["txt2"],None),
                          ("prio_acil",T["warn"],"#261c00"),("prio_gizli",T["danger"],"#220000")]:
            tb.tag_configure(tag,foreground=fg,background=bg if bg else "")
    def _build_inputbar(self):
        bar=ctk.CTkFrame(self,fg_color=T["bg2"],height=66,corner_radius=0); bar.pack(fill="x",side="bottom"); bar.pack_propagate(False)
        inner=ctk.CTkFrame(bar,fg_color="transparent"); inner.pack(fill="x",padx=10,pady=10)
        ctk.CTkButton(inner,text="😊",width=42,height=42,font=("Segoe UI Emoji",17),fg_color=T["bg3"],hover_color=T["border"],corner_radius=8,command=self._open_emoji).pack(side="left",padx=(0,4))
        lbl,col,_=Priority.META[Priority.NORMAL]
        self._prio_btn=ctk.CTkButton(inner,text=lbl,width=86,height=42,font=(T["font_mono"],9,"bold"),fg_color=T["bg3"],hover_color=T["border"],text_color=col,corner_radius=8,command=self._cycle_priority)
        self._prio_btn.pack(side="left",padx=(0,4))
        self._entry=ctk.CTkEntry(inner,placeholder_text="Mesajınızı yazın…",height=42,font=(T["font_mono"],self.config.font_size),fg_color=T["bg3"],border_color=T["border"],text_color=T["txt0"],corner_radius=8)
        self._entry.pack(side="left",fill="x",expand=True,padx=(0,4)); self._entry.bind("<KeyRelease>",self._on_key); self._entry.bind("<Return>",lambda _:self._send())
        self._char_lbl=ctk.CTkLabel(inner,text="0",width=30,font=(T["font_mono"],10),text_color=T["txt2"]); self._char_lbl.pack(side="left",padx=(0,4))
        self._send_btn=ctk.CTkButton(inner,text="↑",width=42,height=42,font=(T["font_mono"],17,"bold"),fg_color=T["accent"],hover_color=T["accent_h"],corner_radius=8,command=self._send)
        self._send_btn.pack(side="right")
    def _set_input_enabled(self, enabled):
        state="normal" if enabled else "disabled"
        self._entry.configure(state=state); self._send_btn.configure(state=state); self._prio_btn.configure(state=state)
        self._entry.configure(placeholder_text="Mesajınızı yazın…" if enabled else "Önce bir kanala katılın")
    def _cycle_priority(self):
        self._current_priority=Priority.next(self._current_priority)
        lbl,col,_=Priority.META[self._current_priority]; self._prio_btn.configure(text=lbl,text_color=col)
    def switch_room(self, room_name):
        self.rm.set_active(room_name); room=self.rm.active_room
        if not room: return
        self._empty.pack_forget(); self._chat_outer.pack(fill="both",expand=True)
        self._room_lbl.configure(text=f"💬  #{room.name}")
        self._chat.configure(state="normal"); self._chat.delete("1.0","end"); self._chat.configure(state="disabled")
        self._msg_count=0
        for s,m,is_self,p in room.messages: self._append(s,m,is_self,p,_save=False)
        self._sys(f"📡  #{room.name}  ·  AES-256 aktif ✓")
        self._count_lbl.configure(text=f"{self._msg_count} mesaj"); self._set_input_enabled(True); self._entry.focus()
    def _wire_ws(self):
        self.ws.on_connecting=lambda: self.after(0,self._status.connecting)
        self.ws.on_connected=lambda: self.after(0,self._on_ws_connected)
        self.ws.on_disconnected=lambda: self.after(0,self._status.disconnected)
        self.ws.on_message=self._on_incoming
        self.ws.on_ping_update=lambda ms: self.after(0,lambda: self._update_quality(ms))
    def _on_ws_connected(self):
        self._status.connected(self.ws.config.uri)
        self.ws.send(json.dumps({"type":"identify","username":self.user_id,"hostname":self._sys_info["hostname"],
                                 "os":self._sys_info["os"],"details":self._sys_info["details"]}))
    def _on_key(self,_):
        n=len(self._entry.get())
        if n>self.config.max_message_length: self._entry.delete(self.config.max_message_length,"end"); n=self.config.max_message_length; self._char_lbl.configure(text_color=T["danger"])
        elif n>self.config.max_message_length*0.8: self._char_lbl.configure(text_color=T["warn"])
        else: self._char_lbl.configure(text_color=T["txt2"])
        self._char_lbl.configure(text=str(n))
    def _send(self):
        msg=self._entry.get().strip(); room=self.rm.active_room
        if not msg or not room: return
        if not self.ws.is_connected: self._sys("⚠ Bağlantı yok.",danger=True); return
        crypto=self.rm.crypto_for(room.name)
        if not crypto: return
        enc=crypto.encrypt(self.user_id,msg,room=room.name,priority=self._current_priority)
        if self.ws.send(enc):
            self.logger.log_msg(f"Siz ({self.user_id})",msg,enc,room=room.name,priority=self._current_priority,verified=True)
            self._append("Siz",msg,True,self._current_priority)
            self._entry.delete(0,"end"); self._char_lbl.configure(text="0",text_color=T["txt2"])
        else: self._sys("⚠ Mesaj gönderilemedi.",danger=True)
    def _on_incoming(self, raw):
        try:
            data=json.loads(raw)
            if isinstance(data,dict):
                t=data.get("type")
                if t=="session_update":
                    self.sessions.clear(); self.sessions.extend(data.get("clients",[]))
                    self.after(0,lambda: self.right_panel.signal_map.update(self.sessions))
                    return
                if t=="room_created":
                    n=data.get("room_name")
                    if n:
                        ok,room,err=self.rm.join(n)
                    if ok and room:
                        if self._sidebar:
                            self.after(0, self._sidebar.refresh)
                            self.after(0, lambda name=n: self._sidebar.set_active(name))
            # Eğer şu an aktif oda yoksa otomatik geç, varsa sadece sidebar'ı güncelle
                        if self.rm.active_room is None or self.rm.active_room.name == n:
                            self.after(0, lambda name=n: self.switch_room(name))
                        else:
                # Aktif odadayken gelen yeni oda → sadece unread işaretle
                            self.after(0, lambda name=n: self._sidebar.mark_unread(name) if self._sidebar else None)
                return
                if t=="location_update":
                    lat=data.get("lat"); lon=data.get("lon"); user=data.get("user","?")
                    if lat is not None and lon is not None:
                        self.after(0,lambda: self.right_panel.location_frame.add_marker(user,lat,lon))
                    return
                if t=="video_call_invite":
                    if self.video_mgr is None:
                        active_room = self.rm.active_room
                        if active_room:
                            self.video_mgr = VideoCallManager(self.ws, self.user_id, active_room.name,
                                                              chat_frame_callback=self._sys)
                        else:
                            return
                    self.video_mgr.handle_invite(data.get("from"))
                    return
                if t=="video_call_accept":
                    if self.video_mgr:
                        self.video_mgr.handle_accept(data.get("from"))
                    return
                if t=="video_call_reject":
                    if self.video_mgr:
                        self.video_mgr.handle_reject(data.get("from"))
                    return
        except: pass

        res=self.rm.decrypt_incoming(raw)
        if res:
            room,decoded=res
            if decoded.get("id")!=self.user_id:
                self.after(0,lambda r=room,d=decoded: self._display(r,d))

    def _display(self, room, data):
        sender=data.get("id","?"); msg=data.get("msg",""); priority=data.get("priority",Priority.NORMAL)
        msg_id=data.get("message_id","")
        self._append(sender,msg,False,priority)
        if room.name!=self.rm.active_room.name and self._sidebar: self._sidebar.mark_unread(room.name)
        if msg_id:
            crypto=self.rm.crypto_for(room.name)
            if crypto:
                receipt={"type":"read_receipt","message_id":msg_id,"recipient":self.user_id}
                receipt["hmac"]=hmac.new(crypto._hmac_key,json.dumps(receipt).encode(),hashlib.sha256).hexdigest()
                self.ws.send(json.dumps(receipt))
    def _append(self,sender,msg,is_self,priority=Priority.NORMAL,_save=True):
        if _save:
            room=self.rm.active_room
            if room: room.messages.append((sender,msg,is_self,priority))
        self._chat.configure(state="normal"); tb=self._chat._textbox
        ts=datetime.now().strftime("%H:%M"); pfx="  ▶ " if is_self else "  ◀ "; stag="me" if is_self else "other"
        pl,_,ptag=Priority.META.get(priority,Priority.META[Priority.NORMAL])
        tb.insert("end",f"\n{pfx}","ts"); tb.insert("end",sender,stag); tb.insert("end",f"  {ts}  ","ts")
        tb.insert("end",f"[{pl}]\n",ptag); tb.insert("end",f"    {msg}\n","body")
        self._chat.configure(state="disabled")
        if self.config.auto_scroll: self._chat.see("end")
        self._msg_count+=1; self._count_lbl.configure(text=f"{self._msg_count} mesaj")
    def _sys(self,text,danger=False):
        self._chat.configure(state="normal"); tag="danger" if danger else "system"
        self._chat._textbox.insert("end",f"\n  ⚙  {text}\n",tag); self._chat.configure(state="disabled")
        if self.config.auto_scroll: self._chat.see("end")
    def _clear(self):
        self._chat.configure(state="normal"); self._chat.delete("1.0","end"); self._chat.configure(state="disabled")
        self._msg_count=0; self._count_lbl.configure(text="")
        if self.rm.active_room: self.rm.active_room.messages.clear()
    def _open_emoji(self): EmojiPicker(self,on_pick=lambda e:(self._entry.insert("end",e),self._entry.focus()))
    def _show_sessions(self): SessionDialog(self,self.sessions,self.ws)

    def _start_video_call(self):
        if not RTC_AVAILABLE:
            self._sys("⚠ Görüntülü arama kütüphanesi yüklü değil.", danger=True)
            return
        active_room = self.rm.active_room
        if not active_room:
            self._sys("⚠ Lütfen önce bir kanala katılın.", danger=True)
            return
        if self.video_mgr is None:
            self.video_mgr = VideoCallManager(self.ws, self.user_id, active_room.name,
                                              chat_frame_callback=self._sys)
        if self.ws.loop and self.ws.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.video_mgr.start_call(), self.ws.loop)
            self._sys("📹 Görüntülü arama daveti gönderildi.")
        else:
            self._sys("⚠ Bağlantı döngüsü hazır değil.", danger=True)

    def _update_quality(self, ping_ms):
        self.cq.add_ping(ping_ms); q=self.cq.quality; signal=self.cq.signal_strength; avg=int(self.cq.average_ping)
        color=T["success"] if q in ("excellent","good") else T["warn"] if q=="fair" else T["danger"]
        self._signal_lbl.configure(text=f"📶 {signal}",text_color=color); self._ping_lbl.configure(text=f"{avg}ms",text_color=color)
        self.right_panel.perf_frame.add_ping(ping_ms)

    def _emergency_zeroize(self):
        # Arka plan görevlerini durdur
        if self.right_panel:
            self.right_panel.stop_background_tasks()
        config=self.config.panic_config
        if config.get("send_panic_msg"):
            active=self.rm.active_room
            if active:
                crypto=self.rm.crypto_for(active.name)
                if crypto:
                    enc=crypto.encrypt(self.user_id,config.get("custom_msg","ACİL!"),room=active.name,priority=Priority.SECRET)
                    self.ws.send(enc)
        if config.get("send_location"):
            try:
                g=geocoder.ip('me')
                if g.ok: self.ws.send(json.dumps({"type":"emergency_location","lat":g.latlng[0],"lon":g.latlng[1],"user":self.user_id}))
            except: pass
        if config.get("destroy_logs"):
            for f in ["securebridge.log", self.logger.log]:
                try:
                    if os.path.exists(f):
                        with open(f,"ba+") as fh: fh.write(os.urandom(os.path.getsize(f)))
                        os.remove(f)
                except: pass
        logger.info("KRİPTOGRAFİK İMHA: Panik!")
        # Pencereyi kapat
        self.winfo_toplevel().destroy()
        # Temiz çıkış
        sys.exit(0)

class SessionDialog(ctk.CTkToplevel):
    def __init__(self, parent, sessions, ws=None):
        super().__init__(parent); self.sessions=sessions; self.ws=ws; self.title("📋 Aktif Oturumlar & OSINT"); self.geometry("600x500")
        self.configure(fg_color=T["bg2"])
        ctk.CTkLabel(self,text="📡 Ağdaki Cihazlar (OSINT)",font=(T["font_mono"],15,"bold"),text_color=T["txt0"]).pack(pady=15)
        self._scroll=ctk.CTkScrollableFrame(self,fg_color="transparent"); self._scroll.pack(fill="both",expand=True,padx=15,pady=5)
        self._refresh_ui(); self._update_loop()
    def _refresh_ui(self):
        for w in self._scroll.winfo_children(): w.destroy()
        if not self.sessions: ctk.CTkLabel(self._scroll,text="Henüz bağlı cihaz yok.",font=(T["font_mono"],11),text_color=T["txt2"]).pack(pady=20); return
        for c in self.sessions:
            f=ctk.CTkFrame(self._scroll,fg_color=T["bg3"],corner_radius=6); f.pack(fill="x",pady=3,padx=2)
            n=c.get("id","?"); ip=c.get("ip","?"); st=c.get("status","?"); os=c.get("os","?"); hn=c.get("hostname","?")
            mac=c.get("mac","?"); det=c.get("details",""); rssi=c.get("rssi","?")
            txt=f"👤 {n}  |  🖥 {hn}  |  💻 {os}\n🌐 {ip}  |  📡 RSSI: {rssi} dBm  |  MAC: {mac}\nDurum: {st}"
            if det: txt+=f"\n📌 {det}"
            ctk.CTkLabel(f,text=txt,font=(T["font_mono"],11),text_color=T["txt0"],justify="left",anchor="w").pack(padx=15,pady=5)
            if self.ws and n:
                ctk.CTkButton(f,text="Kick",width=60,height=25,font=(T["font_mono"],10),fg_color=T["danger"],hover_color="#dc2626",
                              command=lambda t=n: self._kick(t)).pack(padx=5,pady=(0,5))
    def _kick(self,target):
        if self.ws: self.ws.send(json.dumps({"type":"kick","target":target}))
    def _update_loop(self):
        if self.winfo_exists(): self._refresh_ui(); self.after(5000,self._update_loop)

class ConnectionQuality:
    def __init__(self): self._pings=[]
    def add_ping(self,ms): self._pings.append(ms); self._pings=self._pings[-10:]
    @property
    def average_ping(self): return sum(self._pings)/len(self._pings) if self._pings else 0
    @property
    def quality(self):
        avg=self.average_ping
        if avg==0: return "unknown"
        if avg<50: return "excellent"
        if avg<100: return "good"
        if avg<200: return "fair"
        return "poor"
    @property
    def signal_strength(self):
        return {"excellent":"▂▄▆█","good":"▂▄▆_","fair":"▂▄__","poor":"▂___","unknown":"____"}.get(self.quality,"____")

class SystemTray:
    def __init__(self,app,on_show,on_quit): self._app=app; self._on_show=on_show; self._on_quit=on_quit; self._win=None
    def minimize_to_tray(self): self._app.withdraw(); self._create_menu()
    def restore_from_tray(self):
        if self._win: self._win.destroy(); self._win=None
        self._app.deiconify(); self._app.lift()
    def _create_menu(self):
        self._win=ctk.CTkToplevel(self._app); self._win.overrideredirect(True)
        self._win.geometry(f"200x80+{self._app.winfo_x()}+{self._app.winfo_y()}"); self._win.configure(fg_color=T["bg2"])
        ctk.CTkLabel(self._win,text="🔒 SecureBridge",font=(T["font_mono"],12,"bold"),text_color=T["txt0"]).pack(pady=10)
        f=ctk.CTkFrame(self._win,fg_color="transparent"); f.pack(pady=5)
        ctk.CTkButton(f,text="Göster",width=70,height=28,fg_color=T["accent"],hover_color=T["accent_h"],command=self.restore_from_tray).pack(side="left",padx=5)
        ctk.CTkButton(f,text="Çık",width=70,height=28,fg_color=T["danger"],hover_color="#dc2626",command=self._on_quit).pack(side="left",padx=5)

class SecureBridgeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.config=AppConfig.load(); self.title("SecureBridge v6.4"); self.geometry("1080x780"); self.minsize(900,650)
        ctk.set_appearance_mode(self.config.theme)
        self.master_password=""; self.sessions=[]; self.cq=ConnectionQuality()
        self._ws=None; self._chat_log=None; self._sidebar=None; self._chat_frame=None; self._system_tray=None; self._room_manager=None
        self.right_panel = None
        self._show_login()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    def _on_close(self):
        if self._system_tray: self._system_tray.minimize_to_tray()
        else: self.destroy()
    def _show_login(self):
        self._login=LoginFrame(self,on_login=self._handle_login); self._login.pack(fill="both",expand=True)
    def _handle_login(self, username, password):
        logger.info(f"Giriş yapıldı: {username}")
        self.master_password=password; self._room_manager=RoomManager(password); self._chat_log=ChatLogger(self.config.log_file)
        self._ws=WebSocketManager(self.config); self._ws._user_id=username; self._login.destroy()

        main=ctk.CTkFrame(self,fg_color=T["bg0"]); main.pack(fill="both",expand=True)
        self._sidebar=RoomSidebar(main,room_manager=self._room_manager,on_select=self._on_room_select,on_join_request=self._open_join_dialog)
        self._sidebar.pack(side="left",fill="y")
        ctk.CTkFrame(main,fg_color=T["border"],width=1,corner_radius=0).pack(side="left",fill="y")

        chat_area=ctk.CTkFrame(main,fg_color=T["bg0"]); chat_area.pack(side="left",fill="both",expand=True)

        self.right_panel = RightPanel(main, ws=self._ws)
        self.right_panel.pack(side="right", fill="y")

        self._chat_frame=ChatFrame(chat_area,user_id=username,room_manager=self._room_manager,ws=self._ws,logger_=self._chat_log,
                                   config=self.config,on_settings=self._open_settings,sessions=self.sessions,conn_quality=self.cq,
                                   right_panel=self.right_panel)
        self._chat_frame.pack(fill="both",expand=True); self._chat_frame.set_sidebar(self._sidebar)

        self._ws.start()
        self._system_tray=SystemTray(self,on_show=lambda: self._system_tray.restore_from_tray(),on_quit=self.destroy)
    def _on_room_select(self, name):
        self._chat_frame.switch_room(name); self._sidebar.set_active(name)
    def _open_join_dialog(self): AskRoomNameDialog(self, on_join=self._handle_join)
    def _handle_join(self, name):
        ok,room,err=self._room_manager.join(name)
        if ok and room:
            self._sidebar.refresh(); self._chat_frame.switch_room(room.name); self._sidebar.set_active(room.name)
            if self._ws and self._ws.is_connected:
                self._ws.send(json.dumps({"type":"room_created","room_name":room.name}))
        elif self._chat_frame and self._room_manager.active_room:
            self._chat_frame._sys(f"⚠ {err}",danger=True)
    def _open_settings(self): SettingsDialog(self, self.config, on_theme_change=self._apply_theme)
    def _apply_theme(self, theme): ctk.set_appearance_mode(theme)

if __name__=="__main__":
    app=SecureBridgeApp()
    app.mainloop()