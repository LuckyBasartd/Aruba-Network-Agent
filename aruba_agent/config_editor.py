"""
Edit the live /etc/aruba-agent/config.ini from the web UI.

Design notes
------------
* The agent loads its config once at startup. Edits made through the
  Settings UI are written back to disk and only take effect on the
  next service restart — by design (per project decision: a Restart
  Now button rather than a hot-reload). So this module is solely
  concerned with reading the on-disk file fresh and writing it back
  atomically.

* configparser does not preserve interleaved comments. We accept that:
  the [scanner] section's "# Runs first — scans subnets via ICMP..."
  block is documentation, not data. We DO preserve a single header
  comment block (everything before the first [section]) so the file
  identifies itself when read by an admin.

* Sensitive fields (passwords, secrets, secret_key) are never echoed
  back to the browser — that's the caller's responsibility. This
  module just round-trips whatever values it's handed.

* Atomic write: tmp-in-same-dir + os.replace, with file permissions
  preserved from the existing file (or 0640 if it didn't exist).

Threading
---------
ConfigEditor takes no internal lock — the calling code (Flask handler)
is the serialization point. Concurrent writes from multiple operators
hitting Save at the same time would race; in practice this is a
single-operator dashboard so we don't pay the complexity tax.
"""

from __future__ import annotations

import configparser
import io
import logging
import os
import stat
import tempfile
from pathlib import Path
from typing import Dict, Iterable, Optional


log = logging.getLogger(__name__)


_DEFAULT_MODE = 0o640


class ConfigEditor:
    """
    Read/write a single config.ini file. Always reads from disk so the
    UI sees what the agent will see on next start, even if another
    process edited the file in between.
    """

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    # ─── read ────────────────────────────────────────────────────────────────

    def read(self) -> configparser.ConfigParser:
        """
        Parse the file fresh. Returns an empty ConfigParser if the
        file doesn't exist (rather than raising) — the caller will
        usually want to populate it.
        """
        cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
        if self.path.exists():
            cfg.read(self.path, encoding="utf-8")
        return cfg

    def read_header(self) -> str:
        """
        Return everything in the file from the start up to (but not
        including) the first '[section]' line. Used to preserve the
        file's identifying comment block across rewrites.
        """
        if not self.path.exists():
            return ""
        try:
            with self.path.open("r", encoding="utf-8") as f:
                lines = []
                for line in f:
                    stripped = line.lstrip()
                    if stripped.startswith("[") and "]" in stripped:
                        break
                    lines.append(line)
                return "".join(lines)
        except OSError as exc:
            log.warning("ConfigEditor: could not read header (%s)", exc)
            return ""

    # ─── write ───────────────────────────────────────────────────────────────

    def save(
        self,
        cfg: configparser.ConfigParser,
        header: Optional[str] = None,
    ) -> None:
        """
        Write `cfg` to disk atomically. If `header` is given, it is
        prepended verbatim before the first [section]. Permissions
        are inherited from the existing file, or 0640 if creating.

        Caller is expected to have already validated values.
        """
        # Render to a string first
        buf = io.StringIO()
        cfg.write(buf, space_around_delimiters=True)
        body = buf.getvalue()
        text = (header or "") + body

        # Determine target permissions
        try:
            existing_mode = stat.S_IMODE(os.stat(self.path).st_mode)
        except FileNotFoundError:
            existing_mode = _DEFAULT_MODE

        # Atomic write in the same directory
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".config-", suffix=".tmp", dir=str(self.path.parent),
        )
        try:
            os.fchmod(fd, existing_mode)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.path)
            # os.replace doesn't always carry mode forward
            try:
                os.chmod(self.path, existing_mode)
            except OSError:
                pass
            log.info("ConfigEditor: wrote %s", self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # ─── convenience: read, mutate, save in one call ────────────────────────

    def update_section(
        self,
        section: str,
        values: Dict[str, str],
        *,
        remove_keys: Optional[Iterable[str]] = None,
    ) -> None:
        """
        Read, set every key/value in `values` under `[section]`,
        optionally remove `remove_keys`, and save. Creates the section
        if it didn't exist.
        """
        cfg    = self.read()
        header = self.read_header()
        if not cfg.has_section(section):
            cfg.add_section(section)
        for k, v in values.items():
            cfg.set(section, k, str(v) if v is not None else "")
        if remove_keys:
            for k in remove_keys:
                if cfg.has_option(section, k):
                    cfg.remove_option(section, k)
        self.save(cfg, header=header)

    def writable(self) -> bool:
        """
        True if the agent has permission to write to the config file
        (and create temp files in its directory). The Settings UI uses
        this to disable Save buttons up front rather than failing on
        submit.
        """
        try:
            if self.path.exists():
                return os.access(self.path, os.W_OK) and os.access(
                    self.path.parent, os.W_OK | os.X_OK,
                )
            # Doesn't exist yet — can we create it?
            return os.access(self.path.parent, os.W_OK | os.X_OK)
        except OSError:
            return False
