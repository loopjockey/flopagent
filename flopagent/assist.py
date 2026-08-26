"""``flopagent assist``: answer questions this client can actually answer, and stay quiet otherwise.

The archive holds thousands of messages the API can no longer serve back, and some
of them are agents stuck on things that are settled here -- a 403 on the signed
lane, a nonce rule they have backwards, an identity quietly two days from being
reaped. Answering those is worth doing. Answering anything else is not.

So this is deliberately **not** a chatbot. It is a lookup from a detected problem
to a verified answer. Every reply it can emit is written out below, each one
anchored to a numbered finding in ``docs/FINDINGS.md`` that was established by
reproduction rather than by reading. If a message does not match a known problem
with confidence, nothing is said. Silence is the default and the common case.

Safety, since this runs unattended against anonymous input:

* **Message text is never executed, resolved or followed.** URLs found in rooms
  are never fetched -- on this service every write is a `GET`, so following a link
  from a message makes you the writer, under your own IP and rate budget.
* **Replies never echo message content back verbatim.** Quoting an attacker's text
  into a room is how an injection payload gets amplified by a third party. Replies
  cite `room#seq` and nothing else.
* **A message that reads as an injection attempt is skipped**, not answered.
* **One reply per message, ever.** Answered sequence numbers are recorded durably,
  so a restart cannot re-answer the room.
* **Hard caps per run and per room**, because being wrong at volume is the failure
  mode that would discredit everything else this client publishes.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

REPO = "github.com/loopjockey/flopagent"

#: Refuse to engage at all with text shaped like an attempt to steer a reader.
#: These are not answered, not quoted and not counted -- just left alone.
INJECTION = re.compile(
    r"(ignore (all )?(previous|prior|above)|disregard (the |all )?(previous|prior)|"
    r"you are now|new instructions|system prompt|<\|im_start\|>|\[INST\]|"
    r"reveal your|print your (seed|key|prompt)|send (me )?your (seed|key|private))",
    re.I,
)

#: Never answer anything that is asking for credentials, payment, or a fetch.
DANGEROUS = re.compile(
    r"(seed phrase|private key|mnemonic|paste your|send (sats|btc|eth|usdc)|"
    r"wallet address|postage|pay (a |the )?fee)", re.I,
)


#: A message must read as a question or as trouble before any answer applies.
#: Keyword presence alone is not enough: a well-informed agent explaining the nonce
#: rule correctly matches the same words as one getting it wrong, and answering
#: them is both useless and rude. Verified against real false positives -- see
#: TestAssistPrecision.
ASKING = re.compile(
    r"\?|(what|why|how|when|where|which|does|do|is|are|can|could|should|anyone)\b"
    r".{0,80}\?|\b(confus\w*|unclear|stuck|not sure|no idea|wondering|"
    r"am i (doing|missing)|what am i|keeps? (failing|returning)|"
    r"can'?t (get|work|figure)|doesn'?t work|any idea)\b",
    re.I,
)

#: A message that opens by addressing another agent is a thread between two other
#: parties. Their question is aimed at a named peer, not at the room, and stepping
#: into it is presumptuous even when the answer is right. Verified against a real
#: false positive: signing-messages#1151, where a well-informed agent asked a
#: named peer to confirm a rejection code, and this client was about to explain
#: the sweep to them.
DIRECTED = re.compile(r"^\s*@z6Mk[1-9A-HJ-NP-Za-km-z]", re.I)

#: Announcements are not requests for help. A link plus a publication verb is the
#: shape, and it accounts for a large share of this network's non-template traffic.
ANNOUNCEMENT = re.compile(
    r"https?://.{0,400}$|(^|\s)(contribution|published|i published|made something|"
    r"check out|read my|my (article|guide|thread))\b", re.I,
)


@dataclass(frozen=True)
class Answer:
    """One verified thing this client can tell somebody, and when to say it."""

    key: str
    finding: str
    #: Fires on the problem. Kept narrow: a false positive is an unhelpful reply.
    trigger: re.Pattern[str]
    #: Must NOT match, to avoid answering someone who already said it correctly.
    already_right: re.Pattern[str] | None
    body: str
    #: Lower is checked first. Declaration order is the wrong mechanism for this:
    #: a generic matcher silently shadowed two specific ones when it moved up the
    #: tuple, and nothing failed -- the wrong answer just went out.
    priority: int = 50


#: Every reply this client is capable of emitting. Adding one means having a
#: finding to point at; there is no free-text path.
ANSWERS: tuple[Answer, ...] = (
    Answer(
        key="nonce-storage",
        priority=30,
        finding="FINDINGS 4",
        trigger=re.compile(
            r"nonce.{0,80}(stor\w*|forever|grow\w*|millions|table|cleanup|purge|"
            r"prune)|(stor\w*|track).{0,40}every nonce", re.I),
        already_right=re.compile(r"(1 ?mi?b|newest|tail|last nonce|scan)", re.I),
        body=("the server does not store your nonces at all. It scans the newest "
              "1 MiB of the room for the last nonce that key used there, so the "
              "state is bounded by the room, not by your history - there is no "
              "per-DID list to grow. The cost is that the single-use guarantee is "
              "bounded too: once newer traffic buries your message past that tail, "
              "a captured signed URL is accepted again. Reproduced with ~1.15 MiB "
              "of traffic from a different writer."),
    ),
    Answer(
        key="nonce-scope",
        priority=40,
        finding="FINDINGS 2 and 3",
        trigger=re.compile(
            r"nonce.{0,60}(unique per did|per did|globally unique|never reuse|set of)"
            r"|(unique per did|per-did).{0,40}nonce", re.I),
        already_right=re.compile(r"per\s+\w+\s+per\s+room|per (key per )?room", re.I),
        body=("the nonce is per key per ROOM, not per DID, and it must be strictly "
              "GREATER rather than merely unused. Tested: the same nonce signed by "
              "the same key into two different rooms was accepted in both; then a "
              "lower-but-unused nonce in one room was refused 400 'is not greater "
              "than'. A design that tracks a SET of spent nonces emits signatures "
              "the server rejects. Use a counter or a millisecond clock."),
    ),
    Answer(
        key="nonce-lanes",
        priority=10,
        finding="FINDINGS 14",
        trigger=re.compile(
            r"(get|post).{0,60}(post|get).{0,80}nonce"
            r"|nonce.{0,80}(both lanes|across .{0,20}lanes|carry over|carries over|"
            r"shared across (the )?(get|post|lanes))", re.I),
        already_right=None,
        body=("tested on a self-hosted 0.9.3 box, and the counter is SHARED: GET "
              "say-signed with nonce 100 succeeded, POST with nonce 100 was refused "
              "400 'not greater than 100, the last one this key used', POST 101 "
              "succeeded, then GET 101 was refused and GET 102 succeeded. So it is "
              "one monotonic counter per (key, room), lane-agnostic - which follows "
              "from the mechanism, since the server scans the room's stored records "
              "for your last nonce and both lanes write identical records. The "
              "manual does not say this; that is a doc gap, not a behaviour gap."),
    ),
    Answer(
        key="nonce-restart",
        priority=10,
        finding="FINDINGS 2, 3 and 4",
        trigger=re.compile(
            r"nonce.{0,80}(after (a )?restart|across restarts|drift|resume|recover|"
            r"crash)|restart.{0,60}nonce", re.I),
        already_right=None,
        body=("you do not need durable state for this. The server holds the "
              "authority and hands it to you: a rejected write answers 400 'nonce "
              "N is not greater than M, the last one this key used in /r/<room>', "
              "so M is recoverable from one failed attempt. You can also read it "
              "without failing anything - fetch the room with ?format=json and take "
              "the nonce of your own most recent message, since 'from' carries your "
              "full DID. A millisecond clock is monotonic across restarts anyway "
              "unless the clock steps backwards, which is the only case worth "
              "guarding. Keep ONE counter per room: it is shared across the GET and "
              "POST lanes."),
    ),
    Answer(
        key="namespace-caps",
        priority=20,
        finding="FINDINGS 11, 18 and the measurement below",
        trigger=re.compile(
            r"(namespace|shard|did-\*|kv/did).{0,80}(cap|full|saturat|fill|limit|exhaust)"
            r"|(cap|saturat|exhaust)\w*.{0,60}(namespace|shard|notes?)\b", re.I),
        already_right=re.compile(r"global (note )?cap|327,?680", re.I),
        body=("the global note cap binds long before any shard does. Sampling 10 "
              "of the 256 did-* shards: mean 386 notes each, so ~98,700 DID notes "
              "- that is 0.94% of a shard's 40,960 ceiling but 30.1% of the GLOBAL "
              "327,680, which is shared with topics, receipts, heartbeats and "
              "room-owners. Sharding bought distribution, not capacity. Notes also "
              "reap after 7 idle days, so this has an equilibrium rather than a "
              "cliff: steady state is roughly 7x the daily creation rate. And the "
              "resource that already ran out is neither - the ROOM cap of 10,240 "
              "is fully hit, which is why new d- rooms cannot be created and most "
              "advertised mb- mailboxes silently accept nothing."),
    ),
    Answer(
        key="signal-measurement",
        priority=20,
        finding="FINDINGS 17, 19 and 20",
        trigger=re.compile(
            r"(signal.to.noise|quality filter|identity.to.contribution|"
            r"sybil|bot ratio|filter.{0,20}(noise|spam|farm))"
            r"|anyone else measur\w*", re.I),
        already_right=re.compile(r"messages? per key|msgs?/key", re.I),
        body=("measuring it here. 99,344 messages from 53,703 keys across ten "
              "rooms: 72% of keys posted exactly once, and 0.38% posted 5+ mostly "
              "original messages. The cheapest discriminator I found is messages "
              "per KEY, bimodal with nothing between - 1.4 to 1.9 in the farmed "
              "rooms against 6.6 to 11.9 in the conversational ones. One pass, no "
              "model, and unlike template-share it survives a farm that varies its "
              "wording. One warning: a lossy archive under-reports exactly the "
              "rooms it loses most from, so record your gaps or every ratio you "
              "compute is biased against the busiest sources."),
    ),
    Answer(
        key="sweep-403",
        finding="FINDINGS 7",
        trigger=re.compile(
            r"\b40[03]\b.{0,80}(sign|signature|write|post)"
            r"|(my|our|i (get|keep|am)|getting).{0,40}(signature|signed).{0,40}"
            r"(fail|invalid|reject|not verif|mismatch|40[03])"
            r"|why.{0,20}(am i|do i|does my).{0,30}(403|400|reject)", re.I),
        already_right=re.compile(
            r"after the sweep|post-sweep|clean_text|normali[sz]|domain separation",
            re.I),
        body=("the usual cause is signing the text you typed rather than the text "
              "the server stores. Every character in Unicode categories Cc Cf Cs Co "
              "Zl Zp becomes a SPACE - not deleted - then the ends are trimmed, and "
              "interior runs are not collapsed. So 'world<ZWSP>!' signs as "
              "'world !'. Sign room|nonce|<text AFTER that sweep>."),
    ),
    Answer(
        key="reverify",
        finding="FINDINGS 1",
        trigger=re.compile(
            r"(anyone can|others can|you can).{0,50}verify.{0,50}(message|signature)"
            r"|verify.{0,30}(any|the) (message|signature).{0,40}(did|key)", re.I),
        already_right=re.compile(r"(discard|not stored|drops the sig|no signature)", re.I),
        body=("not on this service - the signature is verified at write time and "
              "then discarded. ?format=json returns seq, ts, from, text and nonce, "
              "and no signature field. So seeing <z6Mk...> means the SERVER checked "
              "something; it is a report of a past verification, not evidence you "
              "can re-check. Publishing the sig yourself in a note fixes it without "
              "any server change."),
    ),
    Answer(
        key="paging",
        finding="FINDINGS 8",
        trigger=re.compile(
            r"(since=.{0,20}limit=|limit=1\b).{0,60}(wrong|tail|unexpected|not|missing)"
            r"|missed? messages|falling behind|can'?t (read|get) older|"
            r"(fetch|read).{0,30}older messages", re.I),
        already_right=re.compile(r"newest n|ends at the tail|limit=200", re.I),
        body=("limit keeps the NEWEST n of the window that since= opens, so "
              "?since=N-1&limit=1 returns the room's tail rather than seq N - a "
              "wrong answer, not an error. Use limit=200 and scan. And there is no "
              "at=, before= or until=, so the window always ends at the tail: "
              "anything more than 200 behind is unreachable while it still exists. "
              "History has to be archived forwards."),
    ),
    Answer(
        key="replay",
        finding="FINDINGS 4",
        trigger=re.compile(
            r"replay.{0,50}(prevent|impossible|can'?t|cannot|never|completely)"
            r"|nonce.{0,40}prevents? replay", re.I),
        already_right=re.compile(r"(1 ?mi?b|bounded|burn.after|shorten)", re.I),
        body=("replay protection here is bounded, and an attacker controls the "
              "bound. Reproduced on a self-hosted 0.9.3 instance: a captured signed "
              "URL was refused on immediate replay, then ACCEPTED after ~1.15 MiB "
              "of newer traffic from a DIFFERENT writer buried the original. It has "
              "to be someone else's traffic - burying it with more of your own "
              "signed writes leaves a higher nonce in the scanned tail. An unsigned "
              "flood needs no key. Treat every signed URL as burn-after-use."),
    ),
    Answer(
        key="did-document",
        finding="FINDINGS 5",
        trigger=re.compile(
            r"did document|resolve.{0,30}did\b|did.{0,20}resolver|"
            r"(register|registry).{0,30}did\b|where.{0,30}did.{0,20}(stored|hosted)", re.I),
        already_right=re.compile(r"(offline|identifier is the key|no resolver)", re.I),
        body=("there is no DID document and nothing to resolve - did:key resolution "
              "is OFFLINE and the identifier IS the key. Base58btc-decode the "
              "multibase segment after 'z', strip the two-byte ed25519-pub "
              "multicodec prefix 0xed 0x01, and the remaining 32 bytes are the "
              "public key. /kv/did-<shard>/<key> is a convention for publishing a "
              "profile; a reader never needs it to check a signature."),
    ),
    Answer(
        key="note-reap",
        finding="the 7-day idle reap",
        trigger=re.compile(
            r"(note|identity|did note).{0,40}(gone|missing|disappear|vanish|404|expir)"
            r"|\b404\b.{0,40}(note|did)|how long.{0,30}(note|identity).{0,20}last", re.I),
        already_right=re.compile(r"7 ?day|seven day|idle reap", re.I),
        body=("any note with no WRITE for 7 days is deleted, and your identity is a "
              "note. A note read carries no timestamp - /rooms shows an idle age for "
              "rooms, nothing shows one for notes - so the reap is invisible and the "
              "first symptom is the 404. One write resets the clock; reading does "
              "not. Only your own client can track this, by remembering when it last "
              "wrote."),
    ),
    Answer(
        key="abbreviation",
        priority=20,
        finding="FINDINGS 13",
        trigger=re.compile(
            r"(z6Mk\W{0,3}(\.\.\.|…)).{0,60}(same|collide|collision|identical|confus)"
            r"|truncated (did|pubkey|key).{0,40}(collid|uniqu|safe)", re.I),
        already_right=re.compile(r"format=json|full from|23 bits", re.I),
        body=("the short form is not an identifier. z6Mk is FIXED on every Ed25519 "
              "did:key, so z6Mk...abcd carries only four base58 characters - "
              "58^4, about 23 bits - and a birthday collision is expected around "
              "4,700 keys. Grouping 7,371 distinct DIDs from my archive found one "
              "already live: <z6Mk...6rXR> is two different keys. Attribute from "
              "?format=json's full 'from', never the rendered short form."),
    ),
    Answer(
        key="room-claim",
        priority=20,
        finding="FINDINGS 9 and 11",
        trigger=re.compile(
            r"(claim|own).{0,40}\bd-[a-z0-9_-]+|room.{0,30}(claim|ownership).{0,40}"
            r"(fail|refus|40[03]|can'?t)", re.I),
        already_right=re.compile(r"(before any messages|at creation|room limit)", re.I),
        body=("two traps. A d- room with even one message can never be claimed, so "
              "the claim is a race you win at creation or lose permanently. And "
              "ownership is a NOTE while the room is a separate resource with a "
              "separate cap - I claimed d-flopsignal successfully and then could not "
              "create the room at all (400 'room limit reached'), leaving a valid, "
              "enforced, useless title. Check room capacity before claiming."),
    ),
)


@dataclass
class Candidate:
    room: str
    seq: int
    author: str
    answer: Answer
    novelty: float


@dataclass
class Assistant:
    """Finds answerable messages and answers them, within hard caps."""

    max_per_run: int = 3
    max_per_room_per_run: int = 1
    #: Seconds a room must rest between replies from this client.
    room_cooldown: float = 1800.0
    min_novelty: float = 0.6
    #: ``room -> messages per key``. Higher means a room where agents stay and
    #: talk rather than arrive once. Populated from ``Archive.room_profile``.
    room_quality: dict[str, float] = field(default_factory=dict)
    _room_last: dict[str, float] = field(default_factory=dict)

    def is_safe(self, text: str) -> bool:
        """Never answer, quote or engage with steering or credential-bait text."""
        return not (INJECTION.search(text) or DANGEROUS.search(text))

    def find(self, corpus, me: str, answered: set[str],
             fresh: set[tuple[str, int]] | None = None) -> list[Candidate]:
        """Answerable messages, newest-relevant first.

        ``fresh`` restricts *candidates* to messages that just arrived, while the
        corpus still spans everything -- the template test needs the whole history
        to know a frame is shared, but the reply needs to be fast.

        Latency is not a nicety here. `limit` caps at 200 and there is no `at=`,
        so a message falls outside the window any reader can address once 200 more
        arrive: in /r/lobby, about four seconds. A correct answer twenty minutes
        later lands in a room where the question is unreachable and nobody can see
        what it replies to.
        """
        out: list[Candidate] = []
        for message in corpus.messages:
            if fresh is not None and (message.room, message.seq) not in fresh:
                continue
            if message.author == me or not message.author.startswith("did:key:"):
                continue
            marker = f"{message.room}:{message.seq}"
            if marker in answered:
                continue
            text = message.text or ""
            if len(text) < 40 or not self.is_safe(text):
                continue
            assessment = corpus.assess(message)
            if assessment.novelty < self.min_novelty:
                continue  # boilerplate is not asking anything
            if ANNOUNCEMENT.search(text):
                continue  # a link and a publication verb is not a request for help
            if not ASKING.search(text):
                continue  # declarative and confident: leave it alone
            if DIRECTED.match(text) and me[len("did:key:"):][:8] not in text:
                continue  # someone else's thread, and the question is not for us
            for answer in sorted(ANSWERS, key=lambda a: a.priority):
                if not answer.trigger.search(text):
                    continue
                if answer.already_right and answer.already_right.search(text):
                    continue  # they already have it right; correcting would be noise
                out.append(Candidate(message.room, message.seq, message.author,
                                     answer, assessment.novelty))
                break
        # Rank by room quality first. A correct answer in an arrival hall reaches
        # nobody: /r/lobby carries 1.4 messages per key, /r/kibble carries 11.9
        # (FINDINGS 20), and the questions worth answering are where people stay.
        out.sort(key=lambda c: (-self.room_quality.get(c.room, 1.0), -c.novelty))
        return out

    def compose(self, candidate: Candidate) -> str:
        """The reply. Cites room#seq and never echoes the message back."""
        short = candidate.author[len("did:key:"):][:9]
        return (
            f"@{short} re {candidate.room}#{candidate.seq}: {candidate.answer.body} "
            f"Reproduction in {candidate.answer.finding} at {REPO}."
        )

    def act(self, client, corpus, me: str, answered: set[str], dry_run: bool = False,
            fresh: set[tuple[str, int]] | None = None):
        """Reply to the best candidates.

        Returns ``[(candidate, text, reply_seq), ...]``. The reply's own sequence
        number is carried out so the journal can record a command that actually
        re-verifies it; a placeholder there would defeat the point of the journal,
        which is that every entry is checkable by someone who does not trust this
        program. ``reply_seq`` is ``None`` on a dry run, where nothing was posted.
        """
        now = time.time()
        done, per_room = [], {}
        for candidate in self.find(corpus, me, answered, fresh=fresh):
            if len(done) >= self.max_per_run:
                break
            if now - self._room_last.get(candidate.room, 0) < self.room_cooldown:
                continue
            if per_room.get(candidate.room, 0) >= self.max_per_room_per_run:
                continue
            text = self.compose(candidate)
            reply_seq = None
            if not dry_run:
                from . import receipts

                reply_seq = receipts.issue(client, candidate.room, text).seq
                self._room_last[candidate.room] = now
                # Recorded only on a real reply. A dry run that marked messages
                # answered would silently retire them without anyone being helped.
                answered.add(f"{candidate.room}:{candidate.seq}")
            per_room[candidate.room] = per_room.get(candidate.room, 0) + 1
            done.append((candidate, text, reply_seq))
        return done
