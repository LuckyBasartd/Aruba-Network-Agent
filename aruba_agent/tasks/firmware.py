"""
Firmware Updater — ported from arubacx_firmware_upload.py.

Two-phase concurrent update:
  Phase 1 — status check  (all switches in parallel via ThreadPoolExecutor)
  Phase 2 — compliance check; upload image to out-of-compliance switches

Invoke on-demand:
  python main.py [config.ini] --firmware-update
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

from aruba_agent.cx_session import ArubaCXSession

log = logging.getLogger(__name__)


class _ProgressFile:
    """Wraps an open file to log upload progress every 20%.

    Supports use as a context manager so the underlying file is always closed,
    even if an exception occurs during the upload.
    """

    def __init__(self, path: str, ip: str) -> None:
        self._f        = open(path, "rb")
        self._size     = os.path.getsize(path)
        self._seen     = 0
        self._ip       = ip
        self._last_pct = 0

    def read(self, size: int = -1) -> bytes:
        data = self._f.read(size)
        self._seen += len(data)
        if self._size > 0:
            pct = int(self._seen / self._size * 100)
            if pct >= self._last_pct + 20:
                log.info("FW[%s] upload: %d%%", self._ip, pct)
                self._last_pct = pct
        return data

    def __len__(self) -> int:
        return self._size

    def close(self) -> None:
        self._f.close()

    def __enter__(self) -> "_ProgressFile":
        return self

    def __exit__(self, *_) -> None:
        self.close()


class FirmwareUpdater:
    def __init__(
        self,
        ip_list: List[str],
        username: str,
        password: str,
        target_version: str,
        fw_image_path: str,
        max_workers: int = 2,
    ) -> None:
        self.ips            = ip_list
        self.username       = username
        self.password       = password
        self.target_version = target_version
        self.fw_path        = fw_image_path
        self.max_workers    = max_workers

    # ---------------------------------------------------------------- Phase 1

    def _check_status(self, ip: str) -> dict:
        row: dict = {"ip": ip, "status": None, "error": None, "version": "v10.13"}
        with ArubaCXSession(ip, self.username, self.password) as cx:
            if cx.logged_in:
                row["version"] = cx.version
                row["status"]  = cx.get_firmware_status()
                if not row["status"]:
                    row["error"] = cx.error
            else:
                row["error"] = cx.error
        return row

    # ---------------------------------------------------------------- Phase 2

    def _upload(self, item: dict) -> dict:
        ip     = item["ip"]
        fw     = item.get("status")
        result: dict = {"ip": ip, "status": "FAILED", "msg": ""}

        if not fw:
            result["msg"] = "No firmware status from Phase 1"
            return result

        primary_ver   = fw.get("primary_version",   "")
        secondary_ver = fw.get("secondary_version", "")
        booted        = fw.get("booted_image",      "primary")

        if self.target_version in primary_ver or self.target_version in secondary_ver:
            result["status"] = "SKIPPED"
            return result

        partition = "secondary" if booted == "primary" else "primary"
        log.info("FW[%s] uploading %s → partition '%s'", ip, self.target_version, partition)

        with ArubaCXSession(
            ip, self.username, self.password,
            preferred_version=item.get("version"),
        ) as cx:
            if not cx.logged_in:
                result["msg"] = f"Login failed: {cx.error}"
                return result

            url   = f"{cx.base_url}firmware?image={partition}"
            fname = os.path.basename(self.fw_path)
            try:
                with _ProgressFile(self.fw_path, ip) as wrapped:
                    resp = cx._session.post(
                        url,
                        files={"fileupload": (fname, wrapped, "application/octet-stream")},
                        verify=False,
                        timeout=900,
                    )
                if resp.status_code in (200, 201, 202):
                    result["status"] = "UPDATED"
                else:
                    result["msg"] = f"HTTP {resp.status_code}"
            except Exception as exc:
                result["msg"] = str(exc)

        return result

    # --------------------------------------------------------------- run both

    def run(self) -> None:
        if not self.target_version or not self.fw_path:
            log.error("Firmware update: target_version and image_path must be configured in [firmware]")
            return
        if not os.path.exists(self.fw_path):
            log.error("Firmware update: image file not found: %s", self.fw_path)
            return

        # Phase 1 ── status table
        log.info("Firmware update — Phase 1: status check (%d switches, %d workers)",
                 len(self.ips), self.max_workers)
        inventory: List[dict] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for fut in as_completed([ex.submit(self._check_status, ip) for ip in self.ips]):
                data = fut.result()
                inventory.append(data)
                if data["status"]:
                    fw = data["status"]
                    log.info(
                        "%-18s  booted=%-10s  current=%-20s  primary=%-20s  secondary=%s",
                        data["ip"],
                        fw.get("booted_image",      "?"),
                        fw.get("current_version",   "?"),
                        fw.get("primary_version",   "?"),
                        fw.get("secondary_version", "?"),
                    )
                else:
                    log.warning("%-18s  ERROR: %s", data["ip"], data.get("error"))

        # Phase 2 ── compliance & upload
        log.info("Firmware update — Phase 2: compliance & upload (target: %s)", self.target_version)
        stats: Dict[str, List] = {"UPDATED": [], "SKIPPED": [], "FAILED": []}
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for fut in as_completed([ex.submit(self._upload, item) for item in inventory]):
                res = fut.result()
                stats[res["status"]].append(res)
                log.info("%-18s  %s  %s", res["ip"], res["status"], res.get("msg", ""))

        log.info(
            "Firmware complete — Updated: %d  Skipped: %d  Failed: %d",
            len(stats["UPDATED"]), len(stats["SKIPPED"]), len(stats["FAILED"]),
        )
        for item in stats["FAILED"]:
            log.error("FAILED %-18s  %s", item["ip"], item.get("msg", ""))
