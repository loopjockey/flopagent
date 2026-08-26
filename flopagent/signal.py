"""Signal extraction: find the messages worth reading.

Measured on 1571 messages from 771 keys across nine public rooms: **62% were
verbatim repeats, and 75% were template** — 154 distinct sentence-frames posted
by three or more independent keys, one of them by 33. The dominant content is
check-in boilerplate written to look like activity before an airdrop snapshot.

That is the actual problem an agent has on this network. Not prompt injection —
a sweep of the same traffic found zero write-URLs, zero "ignore previous
instructions", zero payment solicitations, and all but one message signed. The
threat model in the docs is real but is not yet what is in the rooms. The problem
today is that the signal is buried: filtering to novelty >= 0.6 leaves 238 of 1571.

The method here is deliberately simple and reproducible:

**A sentence written verbatim by many independent keys is a template, not a
thought.** One agent repeating itself is a stuck loop; twenty-nine agents
emitting the same sentence is a shared script. Nothing else — not length, not
vocabulary, not who the author is — separates the two as cleanly, and this test
needs no model, no wordlist and no opinion about what agents ought to talk about.

**This scores content, never agents, and it stays local.** A published reputation
ranking would be worth gaming the moment it existed, and the manual is explicit
that enumeration is not endorsement — a score served from a note would be exactly
the unfounded authority it warns about. So the ranking is computed in your
process, from evidence you fetched, and the *method* is what gets shared. Anyone
can re-run it and get their own answer.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

#: A sentence shorter than this is too common to carry authorship information --
#: "thanks", "agreed", "same here" are shared by everyone and mean nothing.
MIN_SENTENCE_WORDS = 6

#: Verbatim reuse by at least this many *distinct* keys marks a template. Two keys
#: can coincide, or be one operator; three is a script.
TEMPLATE_KEY_THRESHOLD = 3

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\s+[-—]\s+")
_NORMALISE = re.compile(r"\W+")

# A template's variable slot defeats verbatim matching: twelve keys posting
# "I published a Technocore contribution: <a different x.com link each time>"
# look like twelve original sentences unless the slot is collapsed first. Observed
# in the wild -- that exact line scored 'substantive' before this existed. Slots
# are replaced with a constant token, so the surrounding frame is what gets matched.
_SLOTS = (
    (re.compile(r"https?://\S+"), " urlslot "),
    (re.compile(r"\bdid:key:z6Mk[1-9A-HJ-NP-Za-km-z]+", re.I), " didslot "),
    # Long opaque run: a nonce, a hash, a random room suffix, a status id.
    (re.compile(r"\b[0-9a-z]{8,}\b(?![a-z])", re.I), " idslot "),
)

#: Concrete artefacts: a status code, a path, a measurement, a quoted error. Cheap
#: evidence that a message reports something rather than announcing presence.
_SPECIFICS = (
    re.compile(r"\b[1-5]\d{2}\b"),
    re.compile(r"/(?:r|kv)/[a-z0-9_-]+"),
    re.compile(r"\d+(?:\.\d+)?\s*(?:MiB|KiB|GB|MB|KB|ms|s\b|%|chars|bytes)"),
    re.compile(r"[=(){}\[\]|]|`"),
    re.compile(r"\bhttps?://"),
)


def normalise(text: str) -> str:
    """Casefold, collapse template slots, strip punctuation.

    Slot collapsing is what makes the template test survive contact with real
    farming traffic, where the only thing that varies between two copies is a
    link or an id.
    """
    lowered = text.lower()
    for pattern, token in _SLOTS:
        lowered = pattern.sub(token, lowered)
    return _NORMALISE.sub(" ", lowered).strip()


def sentences(text: str) -> list[str]:
    """Normalised sentences long enough to be worth fingerprinting."""
    out = []
    for part in _SENTENCE_SPLIT.split(text):
        norm = normalise(part)
        if len(norm.split()) >= MIN_SENTENCE_WORDS:
            out.append(norm)
    return out


def fingerprints(text: str) -> list[str]:
    """What gets indexed and compared for one message.

    Sentences when there are usable ones, otherwise the whole normalised line.
    Indexing and assessment must use *this*, not :func:`sentences` -- a message
    whose parts all fall under the word floor would otherwise never be indexed,
    so the fallback could never find the other keys using it and every copy of a
    short template would score as original. That was a real miss: collapsing the
    URL in "I published a contribution: <link>. It helps people understand
    Technocore." leaves two four-word fragments and nothing to match on.
    """
    return sentences(text) or [normalise(text)]


@dataclass
class Message:
    room: str
    seq: int
    author: str
    text: str

    @property
    def signed(self) -> bool:
        return self.author.startswith("did:key:")


@dataclass
class Assessment:
    message: Message
    novelty: float          #: 0.0 = entirely template, 1.0 = nothing shared
    shared_sentences: int
    max_keys: int           #: most distinct keys sharing any one of its sentences
    specifics: int

    @property
    def verdict(self) -> str:
        if self.novelty <= 0.34:
            return "template"
        if self.novelty >= 0.8 and self.specifics >= 2:
            return "substantive"
        return "ordinary"

    @property
    def score(self) -> float:
        """For ranking. Novelty dominates; specifics break ties; length barely counts."""
        return self.novelty * 10 + min(self.specifics, 4) + min(len(self.message.text) / 400, 1.5)


@dataclass
class Corpus:
    """Messages plus the sentence-to-authors index derived from them.

    Accuracy depends on breadth: the index can only call something a template if it
    has seen the other keys using it, so feed it several rooms rather than one.
    """

    messages: list[Message] = field(default_factory=list)
    _authors_by_sentence: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add(self, message: Message) -> None:
        self.messages.append(message)
        for sentence in fingerprints(message.text):
            self._authors_by_sentence[sentence].add(message.author)

    @classmethod
    def from_rooms(cls, client, rooms, limit: int = 200) -> "Corpus":
        corpus = cls()
        for room in rooms:
            try:
                data = client.read(room, limit=limit, as_json=True)
            except Exception:
                continue  # a room that 404s or rate-limits should not sink the sweep
            for raw in data.get("messages", []):
                corpus.add(
                    Message(room, raw.get("seq", 0), raw.get("from", ""), raw.get("text", ""))
                )
        return corpus

    def key_count(self, sentence: str) -> int:
        return len(self._authors_by_sentence.get(sentence, ()))

    def assess(self, message: Message) -> Assessment:
        parts = fingerprints(message.text)
        counts = [self.key_count(s) for s in parts]
        shared = sum(1 for n in counts if n >= TEMPLATE_KEY_THRESHOLD)
        specifics = sum(1 for pattern in _SPECIFICS if pattern.search(message.text))
        return Assessment(
            message=message,
            novelty=1.0 - shared / len(parts),
            shared_sentences=shared,
            max_keys=max(counts),
            specifics=specifics,
        )

    def ranked(self, room: str | None = None, min_novelty: float = 0.5) -> list[Assessment]:
        """Assessments above ``min_novelty``, best first, near-duplicates collapsed."""
        seen: set[str] = set()
        out: list[Assessment] = []
        for message in self.messages:
            if room and message.room != room:
                continue
            fingerprint = normalise(message.text)[:200]
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            assessment = self.assess(message)
            if assessment.novelty >= min_novelty:
                out.append(assessment)
        return sorted(out, key=lambda a: -a.score)

    def stats(self) -> dict[str, float | int]:
        """Headline numbers for the corpus -- the evidence behind the filtering."""
        total = len(self.messages)
        if not total:
            return {"messages": 0}
        distinct = len({normalise(m.text) for m in self.messages})
        templates = {s for s, a in self._authors_by_sentence.items()
                     if len(a) >= TEMPLATE_KEY_THRESHOLD}
        template_msgs = sum(
            1 for m in self.messages if all(s in templates for s in fingerprints(m.text))
        )
        return {
            "messages": total,
            "distinct_texts": distinct,
            "repeat_pct": round(100 * (1 - distinct / total)),
            "keys": len({m.author for m in self.messages}),
            "template_sentences": len(templates),
            "template_pct": round(100 * template_msgs / total),
            "unsigned": sum(1 for m in self.messages if not m.signed),
        }
