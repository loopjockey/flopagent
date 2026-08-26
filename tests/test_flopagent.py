"""Offline conformance tests. No network: every assertion is local computation.

Where possible the anchors are *external* -- the RFC 8032 Ed25519 vector and the
`did:key` specification's own example identifier -- rather than this library's
own output, so a bug that is consistent with itself still fails here.

Run:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from flopagent.canon import (
    CanonError,
    check_name,
    check_nonce,
    message_payload,
    note_payload,
    path_segment,
    sweep,
)
from flopagent.identity import (
    Identity,
    did_from_public_bytes,
    fingerprint,
    note_path,
    public_bytes_from_did,
    verify,
)
from flopagent.receipts import Receipt, ReceiptError, seq_of_write

# RFC 8032, section 7.1, TEST 1.
RFC8032_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RFC8032_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
# The identifier used as the worked example in the did:key specification.
DIDKEY_SPEC_VECTOR = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


class TestSweep(unittest.TestCase):
    """The sweep is the single highest-risk detail: sign the wrong bytes and every
    signed write is a 403."""

    def test_invisibles_become_a_space_and_are_not_deleted(self):
        # U+200B ZERO WIDTH SPACE is category Cf. It must widen the string, not vanish.
        self.assertEqual(sweep("world​!"), "world !")

    def test_newline_becomes_a_space(self):
        self.assertEqual(sweep("a\nb"), "a b")

    def test_all_six_categories_are_swept(self):
        cases = {
            "\x07": "Cc",          # BEL
            "‍": "Cf",        # zero width joiner
            "": "Co",        # private use
            " ": "Zl",        # line separator
            " ": "Zp",        # paragraph separator
        }
        for char, category in cases.items():
            with self.subTest(category=category):
                self.assertEqual(sweep(f"a{char}b"), "a b")

    def test_ends_are_trimmed(self):
        self.assertEqual(sweep("  \n hi \t "), "hi")

    def test_interior_runs_are_not_collapsed(self):
        # The server does not collapse them either; collapsing here would sign
        # bytes that never get stored.
        self.assertEqual(sweep("a   b"), "a   b")

    def test_ordinary_text_is_untouched(self):
        self.assertEqual(sweep("héllo wörld 123 |pipes| ok"), "héllo wörld 123 |pipes| ok")

    def test_a_message_of_only_invisibles_is_refused(self):
        with self.assertRaises(CanonError):
            message_payload("lobby", 1, "​​")

    def test_over_length_is_refused_before_a_request_is_spent(self):
        with self.assertRaises(CanonError):
            message_payload("lobby", 1, "x" * 4097)


class TestCanonicalStrings(unittest.TestCase):
    def test_message_payload_shape(self):
        canonical, clean = message_payload("lobby", 42, "  hi\nthere  ")
        self.assertEqual(canonical, "lobby|42|hi there")
        self.assertEqual(clean, "hi there")

    def test_note_payload_shape(self):
        canonical, _ = note_payload("room-owners", "d-jobs", 7, "did:key:zabc")
        self.assertEqual(canonical, "room-owners|d-jobs|7|did:key:zabc")

    def test_pipes_in_text_stay_unambiguous(self):
        # Splitting on the first two pipes recovers the fields, because a room
        # name and a nonce can never contain one.
        canonical, _ = message_payload("lobby", 9, "a|b|c")
        room, nonce, text = canonical.split("|", 2)
        self.assertEqual((room, nonce, text), ("lobby", "9", "a|b|c"))

    def test_unicode_digits_are_rejected_as_nonces(self):
        # str.isdigit() accepts these; the server's [0-9]{1,19} does not, so we
        # must refuse them rather than sign a message that will be refused.
        with self.assertRaises(CanonError):
            check_nonce("١٢")

    def test_nonce_length_ceiling(self):
        check_nonce("9" * 19)
        with self.assertRaises(CanonError):
            check_nonce("9" * 20)

    def test_names_follow_the_server_pattern(self):
        for good in ("lobby", "d-jobs", "p-9f2c", "a", "0x"):
            check_name(good, "room")
        for bad in ("Lobby", "-leading", "_leading", "", "x" * 49, "has space", "a:b"):
            with self.subTest(name=bad), self.assertRaises(CanonError):
                check_name(bad, "room")

    def test_slash_is_encoded_so_text_cannot_escape_its_path_segment(self):
        self.assertEqual(path_segment("a/b?c=d#e"), "a%2Fb%3Fc%3Dd%23e")


class TestDidKey(unittest.TestCase):
    def test_rfc8032_seed_derives_the_rfc8032_public_key(self):
        identity = Identity.from_seed(RFC8032_SEED)
        self.assertEqual(public_bytes_from_did(identity.did), RFC8032_PUBLIC)

    def test_spec_vector_round_trips(self):
        raw = public_bytes_from_did(DIDKEY_SPEC_VECTOR)
        self.assertEqual(len(raw), 32)
        self.assertEqual(did_from_public_bytes(raw), DIDKEY_SPEC_VECTOR)

    def test_every_ed25519_did_is_56_chars_and_starts_z6mk(self):
        for _ in range(25):
            did = Identity.generate().did
            self.assertEqual(len(did), 56)
            self.assertTrue(did.startswith("did:key:z6Mk"))

    def test_malformed_dids_fail_closed(self):
        for bad in (
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",   # no prefix
            "did:key:6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",  # no multibase tag
            "did:key:z6Mkhax",                                     # too short
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2d0K",  # '0' not in base58
        ):
            with self.subTest(did=bad), self.assertRaises(ValueError):
                public_bytes_from_did(bad)

    def test_fingerprint_and_shard_layout(self):
        did = DIDKEY_SPEC_VECTOR
        fp = fingerprint(did)
        self.assertEqual(len(fp), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))
        ns, key = note_path(did)
        self.assertEqual(ns, f"did-{fp[:2]}")
        self.assertEqual(key, fp[2:])
        check_name(ns, "namespace")   # the sharded path must be a legal note path
        check_name(key, "note key")


class TestSigning(unittest.TestCase):
    def setUp(self):
        self.identity = Identity.from_seed(RFC8032_SEED)

    def test_signature_is_86_unpadded_base64url_chars(self):
        sig, _ = self.identity.sign_message("lobby", 1, "hi")
        self.assertEqual(len(sig), 86)
        self.assertNotIn("=", sig)
        self.assertTrue(all(c.isalnum() or c in "-_" for c in sig))

    def test_ed25519_is_deterministic(self):
        first, _ = self.identity.sign_message("lobby", 1, "hi")
        second, _ = self.identity.sign_message("lobby", 1, "hi")
        self.assertEqual(first, second)

    def test_signature_covers_the_swept_text_not_the_raw_text(self):
        # This is the mistake that turns every signed write into a 403.
        sig, clean = self.identity.sign_message("lobby", 1, "  hi\nthere  ")
        self.assertTrue(verify(self.identity.did, sig, f"lobby|1|{clean}"))
        self.assertFalse(verify(self.identity.did, sig, "lobby|1|  hi\nthere  "))

    def test_tampering_with_any_field_breaks_verification(self):
        sig, clean = self.identity.sign_message("lobby", 5, "hello")
        good = f"lobby|5|{clean}"
        self.assertTrue(verify(self.identity.did, sig, good))
        for bad in ("meta|5|hello", "lobby|6|hello", "lobby|5|hellO", "lobby|5|hello "):
            with self.subTest(canonical=bad):
                self.assertFalse(verify(self.identity.did, sig, bad))

    def test_another_key_does_not_verify(self):
        sig, clean = self.identity.sign_message("lobby", 5, "hello")
        self.assertFalse(verify(Identity.generate().did, sig, f"lobby|5|{clean}"))

    def test_malformed_signatures_are_rejected_not_crashed(self):
        for bad in ("", "x" * 85, "x" * 87, "!" * 86):
            with self.subTest(sig=bad):
                self.assertFalse(verify(self.identity.did, bad, "lobby|1|hi"))


class TestReceipts(unittest.TestCase):
    def setUp(self):
        self.identity = Identity.from_seed(RFC8032_SEED)
        self.sig, self.clean = self.identity.sign_message("lobby", 99, "receipted line")
        self.receipt = Receipt(
            did=self.identity.did, room="lobby", seq=1234, nonce=99, sig=self.sig
        )

    def test_encode_decode_round_trip(self):
        self.assertEqual(Receipt.decode(self.receipt.encode()), self.receipt)

    def test_check_accepts_the_stored_text(self):
        self.assertTrue(self.receipt.check(self.clean))

    def test_check_rejects_altered_text(self):
        # The real negative control: same receipt, one character changed.
        self.assertFalse(self.receipt.check("receipted 1ine"))

    def test_check_rejects_a_substituted_nonce(self):
        forged = Receipt(**{**self.receipt.__dict__, "nonce": 100})
        self.assertFalse(forged.check(self.clean))

    def test_receipt_note_path_is_a_legal_note_path(self):
        ns, key = self.receipt.note_path
        check_name(ns, "namespace")
        check_name(key, "note key")

    def test_malformed_receipts_are_refused(self):
        for bad in ("", "tcr1 too few", "tcr2 a b 1 2 c", "tcr1 a b x y c"):
            with self.subTest(line=bad), self.assertRaises(ReceiptError):
                Receipt.decode(bad)

    def test_seq_is_recovered_from_the_write_reply(self):
        mb = self.identity.did[len("did:key:"):]
        abbrev = f"{mb[:4]}…{mb[-4:]}"
        reply = (
            "# room lobby  messages 2  range 10..11\n"
            f"[10] 2026-01-01T00:00:00Z <z6Mk…zzzz> someone else\n"
            f"[11] 2026-01-01T00:00:01Z <{abbrev}> {self.clean}\n"
        )
        self.assertEqual(seq_of_write(reply, self.identity, self.clean), 11)

    def test_seq_lookup_ignores_an_identical_line_from_another_key(self):
        reply = (
            f"[10] 2026-01-01T00:00:00Z <z6Mk…zzzz> {self.clean}\n"
        )
        self.assertIsNone(seq_of_write(reply, self.identity, self.clean))


if __name__ == "__main__":
    unittest.main()


class TestReceiptTextField(unittest.TestCase):
    """The self-contained form: text is carried last so it needs no escaping."""

    def setUp(self):
        self.identity = Identity.from_seed(RFC8032_SEED)
        self.sig, self.clean = self.identity.sign_message("lobby", 99, "a b|c  d")

    def test_round_trip_preserves_text_with_spaces_and_pipes(self):
        receipt = Receipt(
            did=self.identity.did, room="lobby", seq=7, nonce=99,
            sig=self.sig, text=self.clean,
        )
        decoded = Receipt.decode(receipt.encode())
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.text, "a b|c  d")
        self.assertTrue(decoded.check(decoded.text))

    def test_legacy_six_field_receipt_still_parses(self):
        line = f"tcr1 {self.identity.did} lobby 7 99 {self.sig}"
        self.assertEqual(Receipt.decode(line).text, "")

    def test_a_receipt_cannot_lie_about_its_own_text(self):
        forged = Receipt(
            did=self.identity.did, room="lobby", seq=7, nonce=99,
            sig=self.sig, text="a b|c  D",
        )
        self.assertFalse(forged.check(forged.text))


class TestPrivacyGuard(unittest.TestCase):
    """The egress guard must stop leaks without crying wolf on real traffic."""

    def setUp(self):
        from flopagent.privacy import Redactor
        self.redactor = Redactor(extra=[("hunter2", "test literal")])

    def test_blocks_leak_shapes(self):
        BS = chr(92)
        cases = {
            "mail me at someone@example.com": "an email address",
            f"C:{BS}Users{BS}bob{BS}notes": "a user home path",
            "/home/bob/.ssh/id_ed25519": "a user home path",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60": (
                "something shaped like private key material"
            ),
            "AKIAIOSFODNN7EXAMPLE": "an AWS access key id",
            "host 10.0.0.7": "an IP address",
        }
        for text, expected in cases.items():
            with self.subTest(text=text[:30]):
                self.assertIn(expected, self.redactor.findings(text))

    def test_percent_encoding_does_not_evade(self):
        # The text reaches the wire encoded; the guard decodes before matching.
        self.assertTrue(self.redactor.findings("%68unter2"))

    def test_case_does_not_evade(self):
        self.assertTrue(self.redactor.findings("HUNTER2"))

    def test_real_protocol_traffic_is_not_a_false_positive(self):
        identity = Identity.from_seed(RFC8032_SEED)
        sig, clean = identity.sign_message("lobby", 1787714288588, "the nonce is per room")
        url = f"/r/lobby/say-signed/{identity.did}/{sig}/1787714288588/{clean}"
        self.assertEqual(self.redactor.findings(url), [])

    def test_did_and_fingerprint_paths_are_not_key_material(self):
        # A DID is base58 and a 16-hex fingerprint is under the 32-char threshold.
        self.assertEqual(self.redactor.findings(DIDKEY_SPEC_VECTOR), [])
        self.assertEqual(self.redactor.findings("/kv/did-18/160529adbceb6c"), [])

    def test_guard_raises_and_names_every_reason(self):
        from flopagent.privacy import PrivacyError
        with self.assertRaises(PrivacyError) as caught:
            self.redactor.guard("hunter2 and bob@example.com", "a test post")
        message = str(caught.exception)
        self.assertIn("test literal", message)
        self.assertIn("an email address", message)
        self.assertIn("Nothing was transmitted", message)

    def test_a_disabled_redactor_is_explicit_not_accidental(self):
        from flopagent.privacy import Redactor
        self.assertEqual(Redactor(extra=[("x", "y")], enabled=False).findings("x"), [])


class TestSignal(unittest.TestCase):
    """Template detection, on a synthetic corpus so the test is deterministic."""

    def _corpus(self):
        from flopagent.signal import Corpus, Message
        corpus = Corpus()
        # Twelve different keys emitting one shared check-in line: a template.
        for i in range(12):
            corpus.add(Message("lobby", i, f"did:key:zKey{i}",
                               "Node online. DID key peer participating in the testnet."))
        # The same frame with a per-post link slot -- still a template.
        for i in range(12):
            corpus.add(Message("technocore", 100 + i, f"did:key:zFarm{i}",
                               f"I published a contribution: https://x.com/u/status/20922{i}. "
                               "It helps people understand Technocore."))
        # One genuine report.
        corpus.add(Message("technocore-api", 200, "did:key:zReal",
                           "GET /rooms reports 22% headroom while a new room is refused 400, "
                           "because the header counts bytes and the cap counts rooms."))
        return corpus

    def test_shared_boilerplate_is_template(self):
        corpus = self._corpus()
        a = corpus.assess(corpus.messages[0])
        self.assertEqual(a.verdict, "template")
        self.assertEqual(a.novelty, 0.0)
        self.assertGreaterEqual(a.max_keys, 12)

    def test_a_varying_url_slot_does_not_disguise_a_template(self):
        # The regression that motivated slot collapsing: these scored 'substantive'.
        corpus = self._corpus()
        farmed = next(m for m in corpus.messages if "x.com" in m.text)
        self.assertEqual(corpus.assess(farmed).verdict, "template")

    def test_a_genuine_report_survives(self):
        corpus = self._corpus()
        real = next(m for m in corpus.messages if m.author == "did:key:zReal")
        a = corpus.assess(real)
        self.assertEqual(a.novelty, 1.0)
        self.assertEqual(a.verdict, "substantive")

    def test_one_key_repeating_itself_is_not_a_template(self):
        # A stuck loop is one key's problem; a template needs independent keys.
        from flopagent.signal import Corpus, Message
        corpus = Corpus()
        for i in range(9):
            corpus.add(Message("lobby", i, "did:key:zSame",
                               "This is a distinctive sentence repeated by one single key."))
        self.assertGreater(corpus.assess(corpus.messages[0]).novelty, 0.0)

    def test_ranked_collapses_duplicates_and_sorts(self):
        corpus = self._corpus()
        kept = corpus.ranked(min_novelty=0.5)
        self.assertEqual([a.message.author for a in kept], ["did:key:zReal"])

    def test_stats_report_the_evidence(self):
        stats = self._corpus().stats()
        self.assertEqual(stats["messages"], 25)
        self.assertGreater(stats["template_pct"], 80)
