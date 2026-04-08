"""
Unified AOS-CX REST API session.

Handles:
  - API version fallback  (v10.13 → v10.10 → v10.04)
  - CSRF token injection
  - Auto re-authentication on 401
  - Context manager (auto-logout on exit)
  - High-level helpers: is_reachable, get_hostname, backup, cli, firmware status
"""

from __future__ import annotations

from typing import Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ArubaCXSession:
    _DEFAULT_VERSIONS = ["v10.13", "v10.10", "v10.04"]

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        preferred_version: Optional[str] = None,
    ) -> None:
        # Build version priority list without duplicates
        versions = ([preferred_version] if preferred_version else []) + self._DEFAULT_VERSIONS
        seen: Dict[str, None] = {}
        self._versions: List[str] = [
            v for v in versions if not (v in seen or seen.update({v: None}))  # type: ignore[func-returns-value]
        ]

        self.host       = host
        self._creds     = {"username": username, "password": password}
        self._session   = requests.Session()
        self._session.verify = verify_ssl
        self.base_url:  Optional[str] = None
        self.version:   Optional[str] = None
        self.logged_in: bool = False
        self.error:     str  = ""

    # ------------------------------------------------------------------ auth

    def login(self) -> bool:
        for ver in self._versions:
            url = f"https://{self.host}/rest/{ver}/login"
            try:
                resp = self._session.post(
                    url,
                    params=self._creds,
                    headers={"x-use-csrf-token": "true"},
                    verify=False,
                    timeout=10,
                )
                if resp.status_code == 200:
                    self.base_url = f"https://{self.host}/rest/{ver}/"
                    self.version  = ver
                    csrf = resp.headers.get("x-csrf-token")
                    if csrf:
                        self._session.headers.update({"x-csrf-token": csrf})
                    self.logged_in = True
                    return True
                if resp.status_code == 401:
                    self.error = "Authentication failed"
                    return False
                # 404 → try next version
            except requests.exceptions.RequestException as exc:
                err = str(exc)
                if any(kw in err for kw in ("Connection refused", "timed out", "Timeout")):
                    self.error = err
                    return False
                self.error = err
        self.error = self.error or "All API versions failed"
        return False

    def logout(self) -> None:
        if not self.logged_in or not self.base_url:
            return
        try:
            self._session.post(self.base_url + "logout", verify=False, timeout=5)
        except Exception:
            pass
        finally:
            self.logged_in = False

    def __enter__(self) -> "ArubaCXSession":
        self.login()
        return self

    def __exit__(self, *_) -> None:
        self.logout()

    # ------------------------------------------------------- raw HTTP helpers

    def _get(self, endpoint: str, **kw) -> Optional[requests.Response]:
        if not self.base_url:
            return None
        try:
            resp = self._session.get(self.base_url + endpoint, verify=False, timeout=15, **kw)
            if resp.status_code == 401:
                self.logged_in = False
                if self.login():
                    resp = self._session.get(self.base_url + endpoint, verify=False, timeout=15, **kw)
            return resp
        except requests.exceptions.RequestException as exc:
            self.error = str(exc)
            return None

    def _put(self, endpoint: str, **kw) -> Optional[requests.Response]:
        if not self.base_url:
            return None
        try:
            return self._session.put(self.base_url + endpoint, verify=False, timeout=15, **kw)
        except requests.exceptions.RequestException as exc:
            self.error = str(exc)
            return None

    def _post(self, endpoint: str, **kw) -> Optional[requests.Response]:
        if not self.base_url:
            return None
        try:
            return self._session.post(self.base_url + endpoint, verify=False, timeout=30, **kw)
        except requests.exceptions.RequestException as exc:
            self.error = str(exc)
            return None

    # ------------------------------------------------------- high-level API

    def is_reachable(self) -> bool:
        resp = self._get("system")
        return resp is not None and resp.status_code == 200

    def get_hostname(self) -> Optional[str]:
        resp = self._get("system")
        if resp and resp.status_code == 200:
            return resp.json().get("hostname")
        return None

    def save_running_to_startup(self) -> bool:
        """Copy running-config → startup-config on the switch."""
        resp = self._put(
            "fullconfigs/startup-config",
            params={"from": f"/rest/{self.version}/fullconfigs/running-config"},
        )
        return resp is not None and resp.status_code in (200, 204)

    def get_startup_config(self) -> Optional[bytes]:
        resp = self._get("fullconfigs/startup-config")
        if resp and resp.status_code == 200 and resp.content:
            return resp.content
        return None

    def cli(self, cmd: str) -> Optional[str]:
        """Execute a show command via the AOS-CX CLI API endpoint."""
        csrf = (
            self._session.cookies.get("csrftoken")
            or self._session.cookies.get("csrf_token")
        )
        headers: Dict[str, str] = {
            "Accept": "text/plain",
            "Content-Type": "application/json",
        }
        if csrf:
            headers["x-csrf-token"] = csrf
        resp = self._post("cli", headers=headers, json={"cmd": cmd})
        if resp and resp.status_code == 200:
            return resp.text
        return None

    def get_firmware_status(self) -> Optional[dict]:
        resp = self._get("firmware")
        if resp and resp.status_code == 200:
            return resp.json()
        return None
