"""Interactive SSH shell session for live console."""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Optional

from utils.helpers import TerminalOutputBuffer
from utils.logger import get_logger

logger = get_logger(__name__)

OutputFn = Callable[[str], None]
StateFn = Callable[[str], None]


class SSHInteractiveSession:
    """Persistent paramiko shell — background reader thread."""

    def __init__(self) -> None:
        self._client = None
        self._channel = None
        self._reader: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._connected = False
        self._host = ""
        self._port = 22
        self._username = ""
        self._output_buffer = TerminalOutputBuffer()

    @property
    def connected(self) -> bool:
        return self._connected and self._channel is not None and not self._channel.closed

    @property
    def endpoint(self) -> str:
        return f"{self._username}@{self._host}:{self._port}"

    def connect(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        *,
        on_output: Optional[OutputFn] = None,
        on_state: Optional[StateFn] = None,
    ) -> None:
        self.disconnect()
        import paramiko

        host = host.strip()
        if not host or not username:
            raise ValueError("Host and username required.")

        if on_state:
            on_state(f"Connecting to {username}@{host}:{port}...")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=20,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=20,
        )
        channel = client.invoke_shell(
            term="xterm-256color",
            width=120,
            height=32,
        )
        channel.settimeout(0.0)

        self._client = client
        self._channel = channel
        self._host = host
        self._port = port
        self._username = username
        self._connected = True
        self._stop.clear()
        self._output_buffer.clear()

        if on_state:
            on_state(f"Connected — {self.endpoint}")

        self._reader = threading.Thread(
            target=self._read_loop,
            args=(on_output,),
            daemon=True,
        )
        self._reader.start()
        time.sleep(0.35)

    def _read_loop(self, on_output: Optional[OutputFn]) -> None:
        while not self._stop.is_set() and self._channel and not self._channel.closed:
            try:
                if self._channel.recv_ready():
                    data = self._channel.recv(65536)
                    if data and on_output:
                        text = self._output_buffer.feed(data.decode("utf-8", errors="replace"))
                        if text:
                            on_output(text)
                elif self._channel.recv_stderr_ready():
                    data = self._channel.recv_stderr(65536)
                    if data and on_output:
                        text = self._output_buffer.feed(data.decode("utf-8", errors="replace"))
                        if text:
                            on_output(text)
                elif self._channel.exit_status_ready():
                    break
                else:
                    time.sleep(0.05)
            except socket.timeout:
                continue
            except Exception as exc:
                if not self._stop.is_set() and on_output:
                    on_output(f"\n[session error: {exc}]\n")
                break

    def send(self, text: str) -> None:
        if not self.connected:
            raise RuntimeError("Not connected.")
        self._channel.send(text)

    def send_line(self, line: str) -> None:
        self.send(line if line.endswith("\n") else line + "\n")

    def send_interrupt(self) -> None:
        """Send SIGINT (Ctrl+C) to remote shell."""
        self.send("\x03")

    def send_eof(self) -> None:
        """Send EOF (Ctrl+D) — may close shell on empty line."""
        self.send("\x04")

    def resize_pty(self, width: int, height: int) -> None:
        if self._channel and not self._channel.closed:
            try:
                self._channel.resize_pty(width=max(40, width), height=max(8, height))
            except Exception:
                logger.debug("PTY resize skipped", exc_info=True)

    def disconnect(self) -> None:
        self._stop.set()
        self._connected = False
        self._output_buffer.clear()
        if self._channel:
            try:
                self._channel.close()
            except Exception:
                pass
            self._channel = None
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
