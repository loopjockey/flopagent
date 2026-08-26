"""An egress guard: refuse to send anything that looks like the operator's data.

technocore.chat is world-readable and permanent enough to matter -- a message is
public the instant it is accepted, and there is no delete. Reviewing each post by
eye does not scale and fails exactly when it matters, so this is enforced in code,
at the transport layer, on the way out.

The check runs on the fully-built, URL-*decoded* request line, not on the text
handed to :meth:`~flopagent.client.Client.say`. That placement is the point:
message text, note values, nicknames, room names and query parameters all funnel
through one place, so a new write path cannot forget to be checked.

Two sources of rules:

* built-ins below -- machine-derived (this host's username and hostname) and
  shape-derived (email addresses, user home paths, private key material);
* ``privacy.deny`` in the working directory, one rule per line, ``#`` for
  comments, ``/slashes/`` for a regex and anything else as a literal substring.
  That file is gitignored and is never itself transmitted.

Fails closed and fails loud: a hit raises before a request is made. There is no
"warn and continue" mode, because a warning that does not stop the send is
indistinguishable from no check at all.
"""

from __future__ import annotations

import getpass
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

DENY_FILE = "privacy.deny"


class PrivacyError(RuntimeError):
    """Outbound content matched a privacy rule. The request was not made."""


def _machine_literals() -> list[tuple[str, str]]:
    """Identifiers belonging to whoever is running this, discovered at runtime.

    Deliberately not hard-coded: the guard should protect the next operator of
    this checkout too, and a literal baked into the source would itself be a leak.
    """
    out: list[tuple[str, str]] = []
    try:
        user = getpass.getuser()
        if user and len(user) >= 3:
            out.append((user, "the local username"))
    except Exception:  # a keyless/serviceaccount environment has no user
        pass
    try:
        host = socket.gethostname()
        if host and len(host) >= 3:
            out.append((host, "this machine's hostname"))
    except Exception:
        pass
    return out


#: ``(compiled pattern, why it is blocked)``. Shape-based, so they catch data this
#: module has never seen. Kept narrow on purpose -- a guard that cries wolf gets
#: switched off, and a switched-off guard protects nothing.
BUILTIN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"), "an email address"),
    (re.compile(r"[A-Za-z]:[\\/](?:Users|home)[\\/][^\\/\s]+", re.I), "a user home path"),
    (re.compile(r"/(?:home|Users)/[^/\s]+"), "a user home path"),
    (re.compile(r"\b[A-Za-z]:[\\/](?:src|dev|code|work|repos)\b", re.I), "a local source path"),
    # 32+ hex characters is key material (an Ed25519 seed is 64). A DID is base58
    # and a signature is base64url, so neither trips this.
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "something shaped like private key material"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a PEM private key"),
    (re.compile(r"\b(?:sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9]{16,}"), "an API token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "an AWS access key id"),
    (re.compile(r"\b(?:api[_-]?key|secret|passwd|password|bearer)\s*[:=]\s*\S+", re.I),
     "a credential assignment"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "an IP address"),
]


@dataclass
class Redactor:
    """Scans outbound content. ``extra`` holds ``(literal, reason)`` rules."""

    extra: list[tuple[str, str]] = field(default_factory=list)
    patterns: list[tuple[re.Pattern[str], str]] = field(
        default_factory=lambda: list(BUILTIN_PATTERNS)
    )
    enabled: bool = True

    @classmethod
    def load(cls, deny_file: str | Path = DENY_FILE) -> "Redactor":
        redactor = cls(extra=_machine_literals())
        path = Path(deny_file)
        if path.exists():
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if len(line) >= 2 and line.startswith("/") and line.endswith("/"):
                    redactor.patterns.append(
                        (re.compile(line[1:-1], re.I), f"a rule from {path}")
                    )
                else:
                    redactor.extra.append((line, f"a rule from {path}"))
        return redactor

    def add(self, literal: str, reason: str = "an explicitly blocked value") -> None:
        self.extra.append((literal, reason))

    def findings(self, text: str) -> list[str]:
        """Every reason ``text`` must not be sent. Empty means it is clear."""
        if not self.enabled:
            return []
        # Scan the decoded form: text reaches the wire percent-encoded, so a name
        # hidden as '%6adoe' is the same leak as a plain 'jdoe'. Never write a real
        # local identifier into this file as an example -- that is itself a leak.
        haystacks = {text, unquote(text)}
        reasons: list[str] = []
        for haystack in haystacks:
            lowered = haystack.lower()
            for literal, reason in self.extra:
                if literal.lower() in lowered and reason not in reasons:
                    reasons.append(reason)
            for pattern, reason in self.patterns:
                if pattern.search(haystack) and reason not in reasons:
                    reasons.append(reason)
        return reasons

    def guard(self, text: str, what: str = "this request") -> None:
        reasons = self.findings(text)
        if reasons:
            raise PrivacyError(
                f"refusing to send {what}: it contains "
                + ", ".join(reasons)
                + ". Nothing was transmitted. technocore.chat is world-readable and "
                "there is no delete, so this is a hard stop -- edit the content, or "
                "add a deliberate exception."
            )
