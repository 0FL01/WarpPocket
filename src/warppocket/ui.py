"""Tkinter interface: status, SOCKS address, connect/disconnect, bounded search.

Network and process work stays on controller workers; this module only renders
state and forwards user intent. Callbacks never block on helper processes.
"""

from __future__ import annotations

import threading
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

from warppocket.controller import ConnectionState
from warppocket.backend import bundled_root

SOCKS_ADDRESS = "127.0.0.1:25344"
PUMP_MS = 100

CONSENT_TEXT = (
    "WarpPocket зарегистрирует это устройство в Cloudflare WARP и сохранит "
    "приватный WireGuard-профиль только локально.\n\n"
    "Продолжение означает принятие условий Cloudflare:\n"
    "https://www.cloudflare.com/application/terms/"
)
PROBE_CONSENT_TEXT = (
    "Для поиска стратегий во время подключения нужен отдельный аккаунт WARP "
    "(второй WireGuard-ключ), чтобы не прерывать активный туннель.\n\n"
    "Продолжение означает принятие условий Cloudflare."
)
STATUS_TEXT = {
    ConnectionState.DISCONNECTED: "Отключено",
    ConnectionState.CONNECTING: "Подключение…",
    ConnectionState.CONNECTED: "Подключено через WARP",
    ConnectionState.ERROR: "Ошибка",
}
IMPORT_TYPES = [("WireGuard profile", "*.conf"), ("Все файлы", "*.*")]


class WarpPocketApp:
    def __init__(self, controller, *, root=None, confirm=None, choose_file=None,
                 show=None, importer=None, diagnostics=None):
        self._controller = controller
        self._confirm = confirm or self._ask
        self._choose_file = choose_file or self._choose
        self._show = show or self._message
        self._importer = importer
        self._diagnostics = diagnostics
        self._closing = threading.Event()
        self._close_done = threading.Event()
        self._progress = ""
        self._notice = ""
        self._root = root or tk.Tk()
        self._build()
        self._root.protocol("WM_DELETE_WINDOW", self.close)
        self._pump_id = self._root.after(PUMP_MS, self._pump)

    # -- widgets -----------------------------------------------------------

    def _build(self):
        root = self._root
        root.title("WarpPocket")
        root.minsize(430, 330)
        background = "#20242b"
        root.configure(bg=background)
        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        for name in (".", "TFrame", "TLabel"):
            style.configure(name, background=background, foreground="#e8e8e8")
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Address.TLabel", font=("Consolas", 16, "bold"))
        style.configure("Hint.TLabel", foreground="#9aa4b2")
        style.configure("Error.TLabel", foreground="#ff8a80", wraplength=380)
        style.configure("TButton", font=("Segoe UI", 10))

        frame = ttk.Frame(root, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="WarpPocket", style="Title.TLabel").pack(anchor="w")
        self._status = ttk.Label(frame, style="Status.TLabel")
        self._status.pack(anchor="w", pady=(10, 2))

        socks = ttk.Frame(frame)
        socks.pack(fill="x", pady=(8, 4))
        ttk.Label(socks, text="SOCKS5 ПРОКСИ", style="Hint.TLabel").pack(anchor="w")
        row = ttk.Frame(socks)
        row.pack(fill="x")
        self._address = tk.StringVar(value=SOCKS_ADDRESS)
        entry = tk.Entry(row, textvariable=self._address, state="readonly",
                         font=("Consolas", 14, "bold"), justify="center",
                         readonlybackground="#2b303a", foreground="#ffffff",
                         relief="flat", highlightthickness=1)
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        self._copy = ttk.Button(row, text="Копировать", command=self._on_copy)
        self._copy.pack(side="left", padx=(8, 0))

        self._connect = ttk.Button(frame, text="Подключиться", command=self._on_connect)
        self._connect.pack(fill="x", pady=(14, 4), ipady=8)
        self._search = ttk.Button(frame, text="Найти новую стратегию", command=self._on_search)
        self._search.pack(fill="x", pady=4, ipady=6)
        self._progress_label = ttk.Label(frame, style="Hint.TLabel", text="")
        self._progress_label.pack(anchor="w", pady=(4, 0))
        self._endpoint = ttk.Label(frame, style="Hint.TLabel", text="")
        self._endpoint.pack(anchor="w")
        self._notice_label = ttk.Label(frame, style="Hint.TLabel", text="")
        self._notice_label.pack(anchor="w", pady=(4, 0), fill="x")

        menu = tk.Menu(root)
        gear = tk.Menu(menu, tearoff=0)
        gear.add_command(label="Импорт основного профиля…", command=lambda: self._on_import("primary"))
        gear.add_command(label="Импорт проверочного профиля…", command=lambda: self._on_import("probe"))
        gear.add_separator()
        gear.add_command(label="Диагностика", command=self._on_diagnostics)
        gear.add_command(label="Условия Cloudflare", command=self._on_terms)
        gear.add_command(label="Лицензии компонентов", command=self._on_licenses)
        menu.add_cascade(label="Настройки", menu=gear)
        root.config(menu=menu)

    # -- events and rendering ---------------------------------------------

    def _pump(self):
        self._pump_id = None
        try:
            if not self._closing.is_set():
                self.process_events()
                self._render()
                self._pump_id = self._root.after(PUMP_MS, self._pump)
            elif self._close_done.is_set():
                self._root.destroy()
            else:
                self._pump_id = self._root.after(PUMP_MS, self._pump)
        except tk.TclError:
            pass

    def stop_pump(self):
        """Cancel the pending pump; used by tests and window teardown."""
        pump_id, self._pump_id = self._pump_id, None
        if pump_id is not None:
            try:
                self._root.after_cancel(pump_id)
            except tk.TclError:
                pass

    def process_events(self):
        for event in self._controller.poll_events():
            self._handle(event)

    def _handle(self, event):
        kind = event.get("type")
        if kind == "state":
            if event.get("state") == ConnectionState.ERROR and event.get("code") == "consent_required":
                self._ask_consent(probe=False)
            if event.get("state") != ConnectionState.CONNECTING:
                self._progress = ""
        elif kind == "connect_progress":
            if event.get("stage") == "trying":
                self._progress = f"Проверка {event.get('endpoint')}…"
        elif kind == "search_started":
            self._progress = f"Поиск через {event.get('role')}"
        elif kind == "search_progress":
            checked, limit = event.get("checked"), event.get("limit")
            found = event.get("found", 0)
            self._progress = f"Проверено {checked} из {limit}; найдено {found}"
        elif kind == "search_cancelled":
            self._progress = ""
            self._notice = "Поиск отменён; сохранённые варианты не изменены."
        elif kind == "search_done":
            self._progress = ""
            if event.get("code") == "consent_required":
                self._ask_consent(probe=True)
            elif event.get("saved"):
                self._notice = ("Сохранено для следующего подключения: "
                                f"{event.get('best')} (проверено {event.get('checked')}).")
            else:
                self._notice = event.get("message") or (
                    f"Найдено {event.get('found')} из {event.get('checked')}.")
        elif kind == "saved":
            self._notice = "Сохранено для следующего подключения."
        elif kind == "warning":
            self._notice = event.get("message", "")
        elif kind == "error":
            if event.get("code") == "consent_required":
                self._ask_consent(probe=False)
            else:
                self._notice = event.get("message", "")

    def _render(self):
        status = self._controller.status()
        state = status["state"]
        searching = status.get("searching", False)
        self._status.configure(text=STATUS_TEXT.get(state, str(state)))
        self._connect.configure(text={ConnectionState.CONNECTED: "Отключиться",
                                      ConnectionState.CONNECTING: "Отмена"}.get(state, "Подключиться"))
        self._search.configure(text="Отменить поиск" if searching else "Найти новую стратегию")
        busy = status.get("busy", False) and state != ConnectionState.CONNECTING
        self._connect.state(["disabled"] if (searching and state != ConnectionState.CONNECTED) or busy or self._closing.is_set() else ["!disabled"])
        self._search.state(["disabled"] if state == ConnectionState.CONNECTING or busy or self._closing.is_set()
                           else ["!disabled"])
        endpoint = status.get("endpoint")
        latency = status.get("latency_ms")
        if endpoint and state == ConnectionState.CONNECTED:
            self._endpoint.configure(text=f"Активный endpoint: {endpoint} · задержка {latency:.0f} мс")
        else:
            self._endpoint.configure(text="")
        if state == ConnectionState.ERROR and status.get("message"):
            self._notice = status["message"]
        self._progress_label.configure(text=self._progress)
        self._notice_label.configure(text=self._notice)

    # -- user actions ------------------------------------------------------

    def _ask_consent(self, probe):
        text = PROBE_CONSENT_TEXT if probe else CONSENT_TEXT
        if self._confirm("Cloudflare WARP", text):
            if probe:
                self._controller.start_search(probe_consent=True)
            else:
                self._controller.connect(consent=True)

    def _on_connect(self):
        if self._controller.status()["state"] in (ConnectionState.CONNECTED, ConnectionState.CONNECTING):
            self._controller.disconnect()
        else:
            self._controller.connect(consent=False)

    def _on_search(self):
        if self._controller.status().get("searching"):
            self._controller.cancel_search()
        else:
            self._progress = ""
            self._controller.start_search(probe_consent=False)

    def _on_copy(self):
        self._root.clipboard_clear()
        self._root.clipboard_append(self._address.get())

    def _on_import(self, role):
        if self._closing.is_set():
            return
        status = self._controller.status()
        if status["state"] != ConnectionState.DISCONNECTED or status.get("searching") or status.get("busy"):
            self._show("Импорт", "Отключитесь и дождитесь завершения поиска перед импортом профиля.")
            return
        if self._importer is None:
            self._show("Импорт", "Импорт недоступен в этом режиме.")
            return
        name = self._choose_file("Импорт профиля", IMPORT_TYPES)
        if not name:
            return
        try:
            self._importer(name, role)
        except Exception as error:
            code = getattr(error, "code", None)
            self._show("Импорт не выполнен", str(error) if code else "Профиль отклонён: некорректный файл.")
            return
        self._show("Импорт", "Профиль сохранён в нормализованном виде и будет использован при подключении.")

    def _on_diagnostics(self):
        text = self._diagnostics() if self._diagnostics else "Диагностика недоступна."
        self._show("Диагностика", text)

    def _on_terms(self):
        self._show("Cloudflare WARP", "Условия: https://www.cloudflare.com/application/terms/")

    def _on_licenses(self):
        self._show("Лицензии", "wireproxy — ISC, wgcf — MIT, списки эндпоинтов ros-scripts — MIT.\n"
                               f"Полные тексты: {bundled_root() / 'vendor/licenses'}")

    # -- shutdown ----------------------------------------------------------

    def close(self):
        if self._closing.is_set():
            return
        self._closing.set()
        self._connect.state(["disabled"])
        self._search.state(["disabled"])

        def stop():
            try:
                self._controller.close()
            finally:
                self._close_done.set()

        threading.Thread(target=stop, name="warppocket-shutdown", daemon=True).start()

    def run(self):
        self._root.mainloop()

    # -- default dialogs ---------------------------------------------------

    def _ask(self, title, text):
        return bool(messagebox.askyesno(title, text, parent=self._root))

    def _choose(self, title, types):
        return filedialog.askopenfilename(title=title, filetypes=types, parent=self._root)

    def _message(self, title, text):
        messagebox.showinfo(title, text, parent=self._root)
