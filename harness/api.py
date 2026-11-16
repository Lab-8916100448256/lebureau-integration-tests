"""Loopback-only authenticated API transport for container fixtures."""

import requests


class API:
    """Send the session cookie only to the container's loopback API.

    This exercises authenticated routes, not browser TLS/cookie handling.
    The browser cookie normally has Secure and /yunohost/api attributes.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.cookie = None

    def request(self, method, path, data=None, params=None):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        response = self.session.request(
            method,
            "http://127.0.0.1:6787" + path,
            data=data,
            params=params,
            headers=headers,
            timeout=240,
            allow_redirects=False,
        )
        # Moulinette returns 204 when a successful action has no return value,
        # including domain_config_set. This is a completed synchronous action.
        if response.status_code == 204:
            return None
        # The same formatter uses 201 for successful POST actions, including
        # DNS previews and pushes, and 200 for reads.
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"API {method} {path}: HTTP {response.status_code}: " + "Request failed"
            )
        try:
            return response.json()
        except ValueError:
            return response.text

    def login(self, username, password):
        self.request(
            "POST", "/login", data={"username": username, "password": password}
        )
        cookie = self.session.cookies.get("yunohost.admin")
        if not cookie:
            raise RuntimeError("API login did not return a session")
        self.cookie = "yunohost.admin=" + cookie
