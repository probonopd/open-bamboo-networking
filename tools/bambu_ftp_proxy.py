#!/usr/bin/env python3
"""bambu_ftp_proxy.py - Plaintext FTP <-> Bambu printer FTPS bridge.

Bambu printers expose a quirky implicit-FTPS daemon on TCP/990 that most
non-FileZilla FTP clients cannot talk to. See `include/obn/ftps.hpp` and
`src/ftps.cpp` in this repo for the full list of quirks; the relevant
ones for this proxy are:

  * Implicit TLS: handshake starts immediately on TCP connect; there is
    no `AUTH TLS` command.
  * Self-signed cert with no usable SAN -> we run with verify=NONE.
  * Login: `USER bblp` / `PASS <printer access code>`.
  * Data channel: PASV only. The PASV reply contains an unreachable IP
    (often 0.0.0.0); we discard it and reconnect to the control host.
  * Data TLS handshake is delayed: send command -> read 150 -> only
    then perform TLS on the data socket. Where supported we reuse the
    control session.
  * MLSD is NOT implemented; only `ls -l`-style LIST works.

This script accepts plaintext FTP from any client on `--listen-host:
--listen-port` (default 127.0.0.1:2121) and translates each session to
the printer's FTPS dialect. One plaintext client = one FTPS session to
the printer.

Two credential modes:
  * If `access_code` is given on the command line, every plaintext
    client is silently logged in to the printer with that code; the
    USER/PASS the client sends is ignored.
  * If `access_code` is omitted, the proxy runs in pass-through mode:
    the username and password the FTP client sends in USER/PASS are
    used verbatim as `USER bblp` / `PASS <code>` against the printer.
    Wrong code -> 530 from the proxy, the client may retry.

Usage:
    python3 bambu_ftp_proxy.py <printer_ip> [<access_code>] [-v]
    lftp -u bblp,<access_code> ftp://127.0.0.1:2121
    curl --user bblp:<access_code> ftp://127.0.0.1:2121/
"""
from __future__ import annotations

import argparse
import logging
import re
import socket
import ssl
import sys
import threading
from typing import Callable, Dict, Optional, Tuple

LOG = logging.getLogger("bambu_ftp_proxy")

# Matches the "(h1,h2,h3,h4,p1,p2)" tuple in a PASV reply.
PASV_RE = re.compile(r"\((\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)")

# FTP commands that need a prepared PASV/EPSV listener and stream data.
DATA_COMMANDS = {"LIST", "NLST", "RETR", "STOR"}

# Commands the proxy is happy to acknowledge before the printer-side
# session is established.
PRELOGIN_COMMANDS = {"USER", "PASS", "QUIT", "FEAT", "OPTS", "SYST", "NOOP"}


# -------------------------------------------------------------------------
# Printer-side FTPS client
# -------------------------------------------------------------------------


class PrinterError(Exception):
    """Raised when the printer FTPS session is unusable."""


class PrinterFtps:
    """Minimal implicit-FTPS client tailored to Bambu printer quirks.

    Mirrors the C++ obn::ftps::Client in `src/ftps.cpp` closely enough
    that the same printers work without any additional probing.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        control_timeout: float,
        data_timeout: float,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.control_timeout = control_timeout
        self.data_timeout = data_timeout

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Bambu firmware negotiates TLS 1.2 (see src/ftps.cpp). Rely on
        # the SSL library default minimum (TLS 1.2+); do not set
        # minimum_version to TLS 1.0/1.1 -- Python 3.13+ deprecates that.
        # OpenSSL 3.x rejects servers that don't support secure
        # renegotiation by default. Bambu's vsftpd does, so this is
        # mostly defensive.
        try:
            ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        except (AttributeError, TypeError):
            pass
        self._ctx = ctx

        self._ctrl: Optional[ssl.SSLSocket] = None
        self._buf = b""

    # ---- control channel ---------------------------------------------

    def connect(self) -> None:
        """TCP-connects to the printer, performs implicit TLS, logs in."""
        raw = socket.create_connection((self.host, self.port), timeout=self.control_timeout)
        raw.settimeout(self.control_timeout)
        try:
            self._ctrl = self._ctx.wrap_socket(raw, server_hostname=self.host)
        except (ssl.SSLError, OSError) as e:
            try:
                raw.close()
            except OSError:
                pass
            raise PrinterError(f"TLS handshake to {self.host}:{self.port} failed: {e}") from e

        code, body = self._read_reply()
        if code != 220:
            raise PrinterError(f"no 220 banner: {code} {body!r}")
        LOG.debug("printer banner: %s", body)

        code, body = self.cmd(f"USER {self.username}")
        if code == 331:
            code, body = self.cmd(f"PASS {self.password}", redact=True)
        if code != 230:
            raise PrinterError(f"login rejected ({code}): {body}")

        for line in ("TYPE I", "PBSZ 0", "PROT P"):
            code, body = self.cmd(line)
            if code != 200:
                raise PrinterError(f"{line!r} rejected ({code}): {body}")

        LOG.info("logged in to printer %s as %s", self.host, self.username)

    def cmd(self, line: str, *, redact: bool = False) -> Tuple[int, str]:
        if self._ctrl is None:
            raise PrinterError("control channel is not open")
        LOG.debug("printer < %s", "<redacted>" if redact else line)
        wire = (line + "\r\n").encode("utf-8", errors="replace")
        try:
            self._ctrl.sendall(wire)
        except (OSError, ssl.SSLError) as e:
            raise PrinterError(f"sending {line!r} failed: {e}") from e
        return self._read_reply()

    def read_reply(self) -> Tuple[int, str]:
        """Public form of `_read_reply` (used after data transfers)."""
        return self._read_reply()

    def _read_line(self) -> str:
        while b"\n" not in self._buf:
            try:
                chunk = self._ctrl.recv(4096) if self._ctrl is not None else b""
            except (OSError, ssl.SSLError) as e:
                raise PrinterError(f"recv on control failed: {e}") from e
            if not chunk:
                raise PrinterError("printer closed control connection")
            self._buf += chunk
        nl = self._buf.index(b"\n")
        line = self._buf[:nl]
        self._buf = self._buf[nl + 1:]
        if line.endswith(b"\r"):
            line = line[:-1]
        return line.decode("utf-8", errors="replace")

    def _read_reply(self) -> Tuple[int, str]:
        first = self._read_line()
        LOG.debug("printer > %s", first)
        if len(first) < 4 or not first[:3].isdigit():
            raise PrinterError(f"bad reply line: {first!r}")
        code = int(first[:3])
        accumulated = [first]
        if first[3] == "-":
            while True:
                line = self._read_line()
                LOG.debug("printer > %s", line)
                accumulated.append(line)
                if (
                    len(line) >= 4
                    and line[:3].isdigit()
                    and int(line[:3]) == code
                    and line[3] == " "
                ):
                    break
        # Strip the leading "NNN " / "NNN-" from each line for the body
        # we pass back; callers don't need to re-parse the code.
        body_lines = []
        for ln in accumulated:
            if len(ln) >= 4 and ln[:3].isdigit() and ln[3] in (" ", "-"):
                body_lines.append(ln[4:])
            else:
                body_lines.append(ln)
        return code, "\n".join(body_lines)

    # ---- data channel -------------------------------------------------

    def open_data_socket(self) -> socket.socket:
        """Sends PASV and returns a *raw* TCP socket connected to the
        printer's data port. The TLS handshake is delayed until after
        the actual data command is acknowledged with 150."""
        code, body = self.cmd("PASV")
        if code != 227:
            raise PrinterError(f"PASV rejected ({code}): {body}")
        m = PASV_RE.search(body)
        if not m:
            raise PrinterError(f"PASV body unparseable: {body!r}")
        p1, p2 = int(m.group(5)), int(m.group(6))
        port = p1 * 256 + p2
        # Discard the printer-supplied IP (often 0.0.0.0 / private) and
        # reconnect to the control host - same trick as
        # `open_data_tcp` in src/ftps.cpp.
        try:
            sock = socket.create_connection((self.host, port), timeout=self.data_timeout)
        except OSError as e:
            raise PrinterError(
                f"data tcp connect to {self.host}:{port} failed: {e}"
            ) from e
        sock.settimeout(self.data_timeout)
        return sock

    def wrap_data_tls(self, sock: socket.socket) -> ssl.SSLSocket:
        """Wraps a connected data socket with TLS, reusing the control
        session where supported."""
        ssock = self._ctx.wrap_socket(
            sock,
            server_hostname=self.host,
            do_handshake_on_connect=False,
        )
        # Reuse the control channel session. Some FTPS servers
        # (pureftpd hardened, vsftpd with require_ssl_reuse=YES) refuse
        # otherwise. Bambu firmware doesn't enforce this today but
        # mirroring the C++ code keeps us portable.
        try:
            if self._ctrl is not None:
                ctrl_session = self._ctrl.session
                if ctrl_session is not None:
                    ssock.session = ctrl_session
        except (ssl.SSLError, AttributeError, OSError) as e:
            LOG.debug("data session reuse skipped: %s", e)
        try:
            ssock.do_handshake()
        except (ssl.SSLError, OSError) as e:
            try:
                ssock.close()
            except OSError:
                pass
            raise PrinterError(f"data TLS handshake failed: {e}") from e
        return ssock

    def close(self) -> None:
        if self._ctrl is None:
            return
        try:
            self._ctrl.sendall(b"QUIT\r\n")
            try:
                self._ctrl.settimeout(1.0)
                self._read_reply()
            except (PrinterError, OSError, ssl.SSLError):
                pass
        except (OSError, ssl.SSLError):
            pass
        try:
            self._ctrl.unwrap()
        except (OSError, ssl.SSLError):
            pass
        try:
            self._ctrl.close()
        except OSError:
            pass
        self._ctrl = None


# -------------------------------------------------------------------------
# Plaintext FTP server side: per-client session
# -------------------------------------------------------------------------


def parse_ls_name(line: str) -> Optional[str]:
    """Extract the filename from an `ls -l` style listing line.

    Mirrors the trailing-name logic in `src/ftps_parse.hpp::parse_ls_line`
    so NLST output matches what LIST advertises."""
    if not line:
        return None
    parts = line.split(None, 8)
    if len(parts) < 9:
        return None
    name = parts[8]
    arrow = name.find(" -> ")
    if arrow != -1:
        name = name[:arrow]
    return name


class ProxySession:
    """One client thread. Translates plaintext FTP -> printer FTPS."""

    HANDLERS: Dict[str, Callable[["ProxySession", str], bool]] = {}

    def __init__(
        self,
        client_sock: socket.socket,
        peer_addr: Tuple[str, int],
        printer_host: str,
        printer_port: int,
        cli_username: str,
        cli_password: Optional[str],
        listen_host: str,
        control_timeout: float,
        data_timeout: float,
    ) -> None:
        self.client = client_sock
        self.peer_addr = peer_addr
        self.printer_host = printer_host
        self.printer_port = printer_port
        # When `cli_password` is not None, every client is logged in to
        # the printer with these creds regardless of what they sent.
        # Otherwise the client's USER/PASS are forwarded verbatim.
        self.cli_username = cli_username
        self.cli_password = cli_password
        self.listen_host = listen_host
        self.control_timeout = control_timeout
        self.data_timeout = data_timeout

        self.client.settimeout(300.0)
        self._buf = b""
        self.printer: Optional[PrinterFtps] = None
        self._pasv_listener: Optional[socket.socket] = None
        self._authed = False
        self._pending_user: Optional[str] = None

    # ---- I/O helpers --------------------------------------------------

    def reply(self, code: int, body: str = "") -> None:
        if not body:
            wire = f"{code}\r\n".encode("utf-8")
        else:
            lines = body.split("\n")
            if len(lines) == 1:
                wire = f"{code} {lines[0]}\r\n".encode("utf-8", errors="replace")
            else:
                # Multiline reply: "NNN-first\r\n second\r\n NNN last\r\n"
                pieces = []
                for i, ln in enumerate(lines):
                    if i == 0:
                        pieces.append(f"{code}-{ln}")
                    elif i == len(lines) - 1:
                        pieces.append(f"{code} {ln}")
                    else:
                        pieces.append(f" {ln}")
                wire = ("\r\n".join(pieces) + "\r\n").encode("utf-8", errors="replace")
        try:
            self.client.sendall(wire)
        except OSError as e:
            LOG.debug("[%s] send to client failed: %s", self.peer_addr, e)
            raise
        LOG.debug(
            "[%s] -> %s", self.peer_addr, wire.rstrip(b"\r\n").decode(errors="replace")
        )

    def _read_command(self) -> Optional[str]:
        while b"\n" not in self._buf:
            try:
                chunk = self.client.recv(4096)
            except (OSError, socket.timeout) as e:
                LOG.debug("[%s] client recv: %s", self.peer_addr, e)
                return None
            if not chunk:
                return None
            self._buf += chunk
            if len(self._buf) > 8192:
                LOG.warning("[%s] command line too long, dropping", self.peer_addr)
                return None
        nl = self._buf.index(b"\n")
        line = self._buf[:nl]
        self._buf = self._buf[nl + 1:]
        if line.endswith(b"\r"):
            line = line[:-1]
        return line.decode("utf-8", errors="replace")

    # ---- main loop ----------------------------------------------------

    def run(self) -> None:
        try:
            self._run()
        except Exception:
            LOG.exception("[%s] session crashed", self.peer_addr)
        finally:
            self._cleanup()

    def _connect_printer(self, username: str, password: str) -> None:
        if self.printer is not None:
            return
        p = PrinterFtps(
            host=self.printer_host,
            port=self.printer_port,
            username=username,
            password=password,
            control_timeout=self.control_timeout,
            data_timeout=self.data_timeout,
        )
        p.connect()
        self.printer = p

    def _run(self) -> None:
        try:
            self.reply(220, f"bambu-ftp-proxy ready (printer {self.printer_host})")
        except OSError:
            return

        while True:
            line = self._read_command()
            if line is None:
                LOG.info("[%s] client disconnected", self.peer_addr)
                return
            if not line.strip():
                continue
            parts = line.strip().split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            redact = cmd == "PASS"
            LOG.debug(
                "[%s] <- %s %s",
                self.peer_addr,
                cmd,
                "<redacted>" if redact else arg,
            )

            if not self._authed and cmd not in PRELOGIN_COMMANDS:
                try:
                    self.reply(530, "Please log in with USER and PASS first")
                except OSError:
                    return
                continue

            handler = self.HANDLERS.get(cmd)
            if handler is None:
                try:
                    self.reply(502, f"Command not implemented: {cmd}")
                except OSError:
                    return
                continue

            try:
                cont = handler(self, arg)
            except PrinterError as e:
                LOG.warning("[%s] printer error: %s", self.peer_addr, e)
                try:
                    self.reply(421, f"Printer session lost: {e}")
                except OSError:
                    pass
                return
            except OSError as e:
                LOG.warning("[%s] socket error: %s", self.peer_addr, e)
                return

            if not cont:
                return

    # ---- command handlers --------------------------------------------

    def _cmd_user(self, arg: str) -> bool:
        self._pending_user = arg if arg else None
        if self.cli_password is not None:
            self.reply(331, "Any password welcome (proxy uses preset creds)")
        else:
            self.reply(331, "Send the printer access code as PASS")
        return True

    def _cmd_pass(self, arg: str) -> bool:
        if self.cli_password is not None:
            user = self.cli_username
            pw = self.cli_password
        else:
            user = self._pending_user or self.cli_username
            pw = arg
            if not pw:
                self.reply(530, "Password required (printer access code)")
                return True
        try:
            self._connect_printer(user, pw)
        except PrinterError as e:
            LOG.warning("[%s] printer login failed: %s", self.peer_addr, e)
            # Allow the client to retry with different creds. Connection
            # to the printer is closed on PrinterFtps.connect() failure
            # before self.printer is set, so the next PASS starts fresh.
            self.reply(530, f"Printer login failed: {e}")
            return True
        self._authed = True
        self.reply(230, "Logged in via proxy")
        return True

    def _cmd_acct(self, arg: str) -> bool:
        self.reply(202, "ACCT not needed")
        return True

    def _cmd_syst(self, arg: str) -> bool:
        self.reply(215, "UNIX Type: L8")
        return True

    def _cmd_feat(self, arg: str) -> bool:
        # Deliberately omit MLSD/MDTM/REST -- Bambu firmware does not
        # implement them. Listing them would only trick clients into
        # issuing commands that bounce back as 500.
        self.reply(211, "Features:\n PASV\n EPSV\n UTF8\n SIZE\n TYPE\nEnd")
        return True

    def _cmd_opts(self, arg: str) -> bool:
        if arg.strip().upper().startswith("UTF8"):
            self.reply(200, "UTF8 OK")
        else:
            self.reply(501, "Unknown option")
        return True

    def _cmd_type(self, arg: str) -> bool:
        a = arg.strip().upper()
        if a in ("I", "L 8", "A", "A N"):
            if self.printer is not None:
                code, body = self.printer.cmd(f"TYPE {a}")
                self.reply(code, body)
            else:
                self.reply(200, f"Type set to {a}")
        else:
            self.reply(504, f"Type not supported: {a}")
        return True

    def _cmd_pwd(self, arg: str) -> bool:
        if self.printer is None:
            self.reply(257, '"/" is current directory')
            return True
        code, body = self.printer.cmd("PWD")
        if code == 257:
            self.reply(257, body)
        else:
            # Printer doesn't expose PWD reliably; fake a response.
            self.reply(257, '"/" is current directory')
        return True

    def _cmd_cwd(self, arg: str) -> bool:
        path = arg if arg else "/"
        if self.printer is None:
            self.reply(503, "Login first")
            return True
        code, body = self.printer.cmd(f"CWD {path}")
        self.reply(code, body)
        return True

    def _cmd_cdup(self, arg: str) -> bool:
        if self.printer is None:
            self.reply(503, "Login first")
            return True
        code, body = self.printer.cmd("CDUP")
        self.reply(code, body)
        return True

    def _cmd_noop(self, arg: str) -> bool:
        if self.printer is not None:
            code, body = self.printer.cmd("NOOP")
            self.reply(code, body)
        else:
            self.reply(200, "OK")
        return True

    def _cmd_size(self, arg: str) -> bool:
        if not arg:
            self.reply(501, "Missing path")
            return True
        if self.printer is None:
            self.reply(503, "Login first")
            return True
        code, body = self.printer.cmd(f"SIZE {arg}")
        self.reply(code, body)
        return True

    def _cmd_dele(self, arg: str) -> bool:
        if not arg:
            self.reply(501, "Missing path")
            return True
        if self.printer is None:
            self.reply(503, "Login first")
            return True
        code, body = self.printer.cmd(f"DELE {arg}")
        self.reply(code, body)
        return True

    def _cmd_quit(self, arg: str) -> bool:
        try:
            self.reply(221, "Goodbye")
        except OSError:
            pass
        return False

    def _cmd_pasv(self, arg: str) -> bool:
        self._close_pasv_listener()
        try:
            listener = self._open_pasv_listener()
        except OSError as e:
            self.reply(425, f"Can't open passive: {e}")
            return True

        port = listener.getsockname()[1]
        local_ip = self._advertised_local_ip()
        if local_ip is None:
            listener.close()
            self.reply(425, "PASV needs an IPv4 listen address; use EPSV")
            return True
        h = local_ip.split(".")
        p1, p2 = port // 256, port % 256
        self._pasv_listener = listener
        self.reply(
            227,
            f"Entering Passive Mode ({h[0]},{h[1]},{h[2]},{h[3]},{p1},{p2}).",
        )
        return True

    def _cmd_epsv(self, arg: str) -> bool:
        a = arg.strip().upper()
        if a == "ALL":
            self.reply(200, "Only EPSV from now on")
            return True
        # Numeric protocol arg ("1"=IPv4, "2"=IPv6) is accepted but
        # ignored - we always advertise on the same family the listener
        # is bound to.
        self._close_pasv_listener()
        try:
            listener = self._open_pasv_listener()
        except OSError as e:
            self.reply(425, f"Can't open passive: {e}")
            return True
        port = listener.getsockname()[1]
        self._pasv_listener = listener
        self.reply(229, f"Entering Extended Passive Mode (|||{port}|).")
        return True

    def _data_cmd(self, cmd: str, arg: str) -> bool:
        if self._pasv_listener is None:
            self.reply(425, "Use PASV/EPSV first")
            return True
        listener = self._pasv_listener
        # PASV listener is one-shot. If anything below fails we still
        # need to release this socket.
        self._pasv_listener = None
        try:
            return self._do_data_transfer(cmd, arg, listener)
        finally:
            try:
                listener.close()
            except OSError:
                pass

    # ---- PASV plumbing -----------------------------------------------

    def _open_pasv_listener(self) -> socket.socket:
        bind_host = self.listen_host or "0.0.0.0"
        # Pick AF based on the bind address.
        if ":" in bind_host:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_host, 0))
        listener.listen(1)
        return listener

    def _advertised_local_ip(self) -> Optional[str]:
        if self.listen_host and self.listen_host not in ("0.0.0.0", "::", ""):
            ip = self.listen_host
        else:
            try:
                ip = self.client.getsockname()[0]
            except OSError:
                ip = "127.0.0.1"
        if ":" in ip:
            return None
        if ip.count(".") != 3:
            return None
        return ip

    def _close_pasv_listener(self) -> None:
        if self._pasv_listener is not None:
            try:
                self._pasv_listener.close()
            except OSError:
                pass
            self._pasv_listener = None

    # ---- data transfer ----------------------------------------------

    def _do_data_transfer(
        self, cmd: str, arg: str, listener: socket.socket
    ) -> bool:
        if self.printer is None:
            self.reply(503, "Login first")
            return True

        try:
            printer_data_raw = self.printer.open_data_socket()
        except PrinterError as e:
            self.reply(425, f"Printer PASV failed: {e}")
            return True

        # Bambu firmware doesn't support NLST cleanly across all builds;
        # use LIST and parse names. parse_ls_line / parse_ls_name handle
        # both date forms.
        printer_cmd = "LIST" if cmd == "NLST" else cmd
        wire = f"{printer_cmd} {arg}".strip() if arg else printer_cmd
        try:
            code, body = self.printer.cmd(wire)
        except PrinterError:
            try:
                printer_data_raw.close()
            except OSError:
                pass
            raise

        if code not in (150, 125):
            try:
                printer_data_raw.close()
            except OSError:
                pass
            self.reply(code, body)
            return True

        # Forward the printer's 150 to the client. Many clients use this
        # as their cue to start streaming for STOR.
        self.reply(code, body if body else "Opening data connection")

        # Accept the client's data socket. Most clients will have
        # already connected by now; the accept either succeeds
        # immediately or waits briefly.
        listener.settimeout(60.0)
        try:
            client_data, _ = listener.accept()
        except (socket.timeout, OSError) as e:
            try:
                printer_data_raw.close()
            except OSError:
                pass
            self.reply(425, f"Client data accept failed: {e}")
            try:
                self.printer.cmd("ABOR")
            except PrinterError:
                raise
            return True
        client_data.settimeout(self.data_timeout)

        try:
            printer_data = self.printer.wrap_data_tls(printer_data_raw)
        except PrinterError as e:
            try:
                client_data.close()
            except OSError:
                pass
            try:
                printer_data_raw.close()
            except OSError:
                pass
            self.reply(425, f"Data TLS handshake failed: {e}")
            return True

        try:
            if cmd == "STOR":
                self._pump_client_to_printer(client_data, printer_data)
            elif cmd == "NLST":
                self._pump_printer_to_client_nlst(client_data, printer_data)
            else:  # LIST, RETR
                self._pump_printer_to_client(client_data, printer_data)
        except OSError as e:
            LOG.warning("[%s] data transfer error: %s", self.peer_addr, e)
        finally:
            self._close_data_pair(client_data, printer_data)

        try:
            done_code, done_body = self.printer.read_reply()
        except PrinterError:
            raise
        self.reply(done_code, done_body if done_body else "Transfer complete")
        return True

    @staticmethod
    def _close_data_pair(client_data: socket.socket, printer_data: ssl.SSLSocket) -> None:
        # Send TLS close_notify so vsftpd cleanly finalises the
        # transfer; mirrors the SSL_shutdown call in src/ftps.cpp.
        try:
            printer_data.unwrap()
        except (OSError, ssl.SSLError):
            pass
        try:
            printer_data.close()
        except OSError:
            pass
        try:
            client_data.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client_data.close()
        except OSError:
            pass

    # ---- byte pumps ---------------------------------------------------

    @staticmethod
    def _pump_printer_to_client(
        client: socket.socket, printer: ssl.SSLSocket
    ) -> None:
        while True:
            try:
                data = printer.recv(64 * 1024)
            except ssl.SSLError as e:
                # OpenSSL 3 raises SSLEOFError for the common "vsftpd
                # closed without close_notify" case; treat as clean EOF.
                if "UNEXPECTED_EOF_WHILE_READING" in str(e) or isinstance(
                    e, getattr(ssl, "SSLEOFError", ())
                ):
                    return
                raise
            if not data:
                return
            try:
                client.sendall(data)
            except OSError:
                return

    @staticmethod
    def _pump_client_to_printer(
        client: socket.socket, printer: ssl.SSLSocket
    ) -> None:
        while True:
            try:
                data = client.recv(64 * 1024)
            except OSError:
                return
            if not data:
                return
            try:
                printer.sendall(data)
            except (OSError, ssl.SSLError):
                return

    @staticmethod
    def _pump_printer_to_client_nlst(
        client: socket.socket, printer: ssl.SSLSocket
    ) -> None:
        buf = b""
        while True:
            try:
                data = printer.recv(64 * 1024)
            except ssl.SSLError as e:
                if "UNEXPECTED_EOF_WHILE_READING" in str(e) or isinstance(
                    e, getattr(ssl, "SSLEOFError", ())
                ):
                    break
                raise
            if not data:
                break
            buf += data
        text = buf.decode("utf-8", errors="replace")
        names = []
        for line in text.splitlines():
            name = parse_ls_name(line)
            if name and name not in (".", ".."):
                names.append(name)
        if names:
            payload = ("\r\n".join(names) + "\r\n").encode("utf-8", errors="replace")
            try:
                client.sendall(payload)
            except OSError:
                pass

    # ---- shutdown -----------------------------------------------------

    def _cleanup(self) -> None:
        self._close_pasv_listener()
        if self.printer is not None:
            try:
                self.printer.close()
            except Exception:
                pass
            self.printer = None
        try:
            self.client.close()
        except OSError:
            pass


# Wire up the dispatch table now that all methods exist.
ProxySession.HANDLERS.update(
    {
        "USER": ProxySession._cmd_user,
        "PASS": ProxySession._cmd_pass,
        "ACCT": ProxySession._cmd_acct,
        "SYST": ProxySession._cmd_syst,
        "FEAT": ProxySession._cmd_feat,
        "OPTS": ProxySession._cmd_opts,
        "TYPE": ProxySession._cmd_type,
        "PWD": ProxySession._cmd_pwd,
        "XPWD": ProxySession._cmd_pwd,
        "CWD": ProxySession._cmd_cwd,
        "XCWD": ProxySession._cmd_cwd,
        "CDUP": ProxySession._cmd_cdup,
        "XCUP": ProxySession._cmd_cdup,
        "NOOP": ProxySession._cmd_noop,
        "SIZE": ProxySession._cmd_size,
        "DELE": ProxySession._cmd_dele,
        "QUIT": ProxySession._cmd_quit,
        "PASV": ProxySession._cmd_pasv,
        "EPSV": ProxySession._cmd_epsv,
        "LIST": lambda self, arg: self._data_cmd("LIST", arg),
        "NLST": lambda self, arg: self._data_cmd("NLST", arg),
        "RETR": lambda self, arg: self._data_cmd("RETR", arg),
        "STOR": lambda self, arg: self._data_cmd("STOR", arg),
    }
)


# -------------------------------------------------------------------------
# main
# -------------------------------------------------------------------------


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="bambu_ftp_proxy",
        description=(
            "Plaintext FTP server that proxies to a Bambu printer's "
            "implicit-FTPS daemon (TCP/990)."
        ),
    )
    p.add_argument("printer_ip", help="Printer LAN IP (e.g. 10.13.1.30)")
    p.add_argument(
        "access_code",
        nargs="?",
        default=None,
        help=(
            "Printer access code shown on the printer screen. If "
            "omitted, the proxy runs in pass-through mode: the FTP "
            "client must send the access code as the PASS password."
        ),
    )
    p.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Address to bind the plaintext FTP server (default: 127.0.0.1)",
    )
    p.add_argument(
        "--listen-port",
        type=int,
        default=2121,
        help="Port for the plaintext FTP server (default: 2121)",
    )
    p.add_argument(
        "--printer-port",
        type=int,
        default=990,
        help="Printer FTPS port (default: 990)",
    )
    p.add_argument(
        "--username",
        default="bblp",
        help="Username for the printer (default: bblp)",
    )
    p.add_argument(
        "--control-timeout",
        type=float,
        default=15.0,
        help="Per-syscall timeout on the printer control channel, seconds",
    )
    p.add_argument(
        "--data-timeout",
        type=float,
        default=120.0,
        help="Per-syscall timeout on data transfers, seconds",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v: INFO, -vv: DEBUG)",
    )
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose == 1:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    family = socket.AF_INET6 if ":" in args.listen_host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((args.listen_host, args.listen_port))
    except OSError as e:
        print(
            f"bind {args.listen_host}:{args.listen_port}: {e}",
            file=sys.stderr,
        )
        return 1
    server.listen(8)

    mode = "preset access code" if args.access_code else "pass-through PASS"
    print(
        f"Listening on ftp://{args.listen_host}:{args.listen_port}/ "
        f"-> printer {args.printer_ip}:{args.printer_port} ({mode})",
        file=sys.stderr,
    )

    try:
        while True:
            try:
                client_sock, peer = server.accept()
            except KeyboardInterrupt:
                break
            except OSError as e:
                LOG.warning("accept failed: %s", e)
                continue
            LOG.info("client connected: %s", peer)
            sess = ProxySession(
                client_sock=client_sock,
                peer_addr=peer,
                printer_host=args.printer_ip,
                printer_port=args.printer_port,
                cli_username=args.username,
                cli_password=args.access_code,
                listen_host=args.listen_host,
                control_timeout=args.control_timeout,
                data_timeout=args.data_timeout,
            )
            t = threading.Thread(
                target=sess.run,
                name=f"ftp-{peer[0]}:{peer[1]}",
                daemon=True,
            )
            t.start()
    finally:
        try:
            server.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
