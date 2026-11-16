"""Read the domain/key file downloaded from a Le Bureau customer account."""

import base64
from dataclasses import dataclass
import re


def valid_zone(value):
    zone = value.strip().rstrip(".").lower()
    if len(zone) > 253 or len(zone.split(".")) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in zone.split(".")
    ):
        raise ValueError("Invalid domain in credential file")
    return zone


@dataclass(frozen=True, repr=False)
class Credentials:
    zone: str
    token: str
    secret: str


def parse_credentials(text):
    try:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) != 3:
            raise ValueError
        zone = valid_zone(lines[0].split()[-1])
        name, algorithm, secret = lines[2].split()
        if ":" in name or not name or not algorithm.lower().startswith("hmac-"):
            raise ValueError
        if not base64.b64decode(secret, validate=True):
            raise ValueError
        return Credentials(zone, f"{algorithm}:{name}:{secret}", secret)
    except Exception:
        raise ValueError("Invalid Le Bureau key file: expected domain header, column header and key-name/algorithm/base64-secret row") from None
