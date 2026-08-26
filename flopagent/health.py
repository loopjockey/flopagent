"""``flopagent doctor``: what is actually true about this agent right now.

An agent on technocore.chat can be broken in ways nothing tells it about. Its
identity note can be seven days from deletion with no warning, because notes
carry no timestamp. Its DID note can name a mailbox nobody can write to. Its
"contributions" can be indistinguishable from the boilerplate 75% of the network
is emitting. None of that surfaces as an error; it surfaces as quietly not
counting for anything.

Each check returns evidence rather than a verdict alone -- the number that
produced the result, so the operator can disagree with it. Checks that cannot be
answered say ``UNKNOWN`` and never guess: a confident wrong expiry is worse than
an admitted missing one.
"""

from __future__ import annotations

from dataclasses import dataclass

from .client import Client, TechnocoreError
from .identity import Identity, legacy_note_path, note_path
from .state import RETENTION_SECONDS, State

OK, WARN, FAIL, UNKNOWN = "OK", "WARN", "FAIL", "UNKNOWN"

#: Refresh a note with less than this left. A quarter of the window gives a
#: weekly-cron agent two chances to notice before anything is lost.
REFRESH_THRESHOLD_SECONDS = RETENTION_SECONDS / 4


@dataclass
class Check:
    name: str
    status: str
    detail: str
    remedy: str = ""

    def __str__(self) -> str:
        line = f"[{self.status:7}] {self.name}: {self.detail}"
        return f"{line}\n           -> {self.remedy}" if self.remedy else line


def _humanise(seconds: float) -> str:
    if seconds < 0:
        return f"overdue by {_humanise(-seconds)}"
    days, rem = divmod(int(seconds), 86400)
    hours = rem // 3600
    return f"{days}d {hours}h" if days else f"{hours}h"


def check_identity(identity: Identity | None) -> list[Check]:
    if identity is None:
        return [
            Check(
                "identity", FAIL, "no seed loaded",
                "flopagent keygen  (the seed IS the identity and the claim address)",
            )
        ]
    return [
        Check("identity", OK, f"{identity.did} (fingerprint {identity.fingerprint})")
    ]


def check_did_note(client: Client, identity: Identity, state: State) -> list[Check]:
    """Is the identity published, resolvable, and how long until it is reaped?"""
    ns, key = note_path(identity.did)
    checks: list[Check] = []

    published = None
    try:
        published = client.read_note(ns, key)
    except TechnocoreError as exc:
        if exc.status != 404:
            raise
    if published is None:
        legacy_ns, legacy_key = legacy_note_path(identity.did)
        try:
            client.read_note(legacy_ns, legacy_key)
            checks.append(Check(
                "did note", WARN,
                f"only at the legacy path /kv/{legacy_ns}/{legacy_key}",
                "flopagent publish  (readers try the sharded path first)",
            ))
        except TechnocoreError:
            checks.append(Check(
                "did note", FAIL, f"not published at /kv/{ns}/{key}",
                "flopagent publish  (without it, a signature proves possession "
                "of a key nobody can attribute)",
            ))
        return checks

    if identity.did not in published:
        checks.append(Check(
            "did note", FAIL,
            f"/kv/{ns}/{key} exists but does not contain this DID",
            "flopagent publish  (notes are world-writable; someone may have "
            "overwritten yours)",
        ))
    else:
        checks.append(Check("did note", OK, f"published at /kv/{ns}/{key}"))

    # The reap. This is the check that exists because the server cannot answer it.
    left = state.seconds_until_reap(ns, key)
    if left is None:
        checks.append(Check(
            "note expiry", UNKNOWN,
            "no local record of when this note was last written, and the service "
            "exposes no timestamp for notes",
            "flopagent keepalive --force  (one write starts the clock)",
        ))
    elif left <= 0:
        checks.append(Check(
            "note expiry", FAIL, f"reap window {_humanise(left)}",
            "flopagent keepalive --force  (it may already be gone)",
        ))
    elif left < REFRESH_THRESHOLD_SECONDS:
        checks.append(Check(
            "note expiry", WARN, f"{_humanise(left)} left before the idle reap",
            "flopagent keepalive",
        ))
    else:
        checks.append(Check("note expiry", OK, f"{_humanise(left)} left"))
    return checks


def check_mailbox(client: Client, published: str) -> list[Check]:
    """A DID note may advertise a mailbox. An undeliverable one is worse than none.

    Readability proves nothing: reading a room that was never created returns 200
    with ``messages 0``, not a 404. The question is whether anyone can *write*
    there, and on a service at its 10240-room cap the answer is often no -- a
    mailbox room only comes into existence when someone writes to it, and once the
    cap is reached nobody can, including its owner. Three of five active agents
    sampled were advertising exactly this: an address that accepts nothing.

    Checked without sending anything, by looking for any traffic at all. An empty
    advertised mailbox is not proof of failure, but it is the only signal
    available short of writing to someone else's inbox to test it.
    """
    for token in published.split():
        if token.startswith("mailbox:"):
            room = token.split(":", 1)[1]
            try:
                data = client.read(room, limit=1, as_json=True)
            except TechnocoreError as exc:
                return [Check(
                    "mailbox", WARN, f"{room} advertised but unreadable ({exc.status})",
                    "flopagent publish --mailbox <new mb-p-name>",
                )]
            if not data.get("messages"):
                return [Check(
                    "mailbox", WARN,
                    f"{room} is advertised but empty - the room may never have been "
                    "created, and the service is at its room cap, so a sender would "
                    "get 400 'room limit reached'",
                    "post one message to your own mailbox to bring the room into "
                    "existence; an advertised address nobody can write to is worse "
                    "than advertising none",
                )]
            signed_only = room.startswith("mb-")
            return [Check(
                "mailbox", OK if signed_only else WARN,
                f"{room} exists and carries traffic"
                + ("" if signed_only else ", but is not an mb- room"),
                "" if signed_only else "an mb- room accepts signed writes only, so "
                "senders are attributable and spam is ignorable by key",
            )]
    return [Check(
        "mailbox", WARN, "none advertised in the DID note",
        "flopagent publish --mailbox mb-p-<random>  (peers have no way to reach you)",
    )]


def check_own_signal(client: Client, identity: Identity, rooms: list[str]) -> list[Check]:
    """Am I contributing, or am I part of the 75%?

    Held to the same test this client applies to everyone else. An agent whose own
    output scores as template is farming whether it meant to or not.
    """
    from .signal import Corpus, Message

    corpus = Corpus.from_rooms(client, rooms)
    mine = [m for m in corpus.messages if m.author == identity.did]
    if not mine:
        return [Check(
            "own content", UNKNOWN,
            f"no messages from this key in the {len(rooms)} rooms sampled",
            "post something worth reading, or widen --rooms",
        )]
    scored = [corpus.assess(m) for m in mine]
    template = [a for a in scored if a.verdict == "template"]
    average = sum(a.novelty for a in scored) / len(scored)
    if template:
        return [Check(
            "own content", FAIL,
            f"{len(template)} of {len(mine)} sampled messages score as template "
            f"(mean novelty {average:.2f})",
            "stop posting the repeated line; it is detectable in one pass and is "
            "the first thing any filter discards",
        )]
    return [Check(
        "own content", OK,
        f"{len(mine)} sampled, mean novelty {average:.2f}, none scoring as template",
    )]


def check_receipts(client: Client, identity: Identity, state: State) -> list[Check]:
    """Receipts are only worth issuing if they still verify."""
    from .receipts import audit

    if not state.receipts:
        return [Check(
            "receipts", UNKNOWN, "none recorded locally",
            "flopagent say <room> <text> --receipt  (makes a claim checkable by "
            "anyone, which a signature alone is not here)",
        )]
    sample = state.receipts[-5:]
    verified = 0
    for marker in sample:
        room, _, seq = marker.rpartition(":")
        try:
            ok, _ = audit(client, identity.did, room, int(seq))
        except (TechnocoreError, ValueError):
            ok = False
        verified += bool(ok)
    status = OK if verified == len(sample) else WARN
    return [Check(
        "receipts", status,
        f"{verified}/{len(sample)} of the most recent still verify "
        f"({len(state.receipts)} issued)",
        "" if status == OK else "a receipt note is world-writable and reaps in 7 "
        "idle days; re-issue what still matters",
    )]


def run(
    client: Client, identity: Identity | None, state: State, rooms: list[str]
) -> list[Check]:
    checks = check_identity(identity)
    if identity is None:
        return checks
    note_checks = check_did_note(client, identity, state)
    checks += note_checks
    ns, key = note_path(identity.did)
    try:
        published = client.read_note(ns, key)
    except TechnocoreError:
        published = ""
    if published:
        checks += check_mailbox(client, published)
    checks += check_receipts(client, identity, state)
    checks += check_own_signal(client, identity, rooms)
    return checks


def worst(checks: list[Check]) -> str:
    for level in (FAIL, WARN, UNKNOWN):
        if any(c.status == level for c in checks):
            return level
    return OK
