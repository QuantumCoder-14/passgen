#!/usr/bin/env python3
import sys, unittest, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import passgen

class TestPassword(unittest.TestCase):
    def test_length_respected(self):
        for n in (1, 8, 20, 64):
            self.assertEqual(len(passgen.password(n)), n)

    def test_uses_secrets_not_random(self):
        src = Path(passgen.__file__).read_text()
        self.assertIn("secrets.choice", src)
        self.assertNotIn("random.choice", src)

    def test_no_symbols_option(self):
        for _ in range(20):
            pw = passgen.password(40, symbols=False)
            self.assertRegex(pw, r"^[A-Za-z0-9]+$")

    def test_avoid_ambiguous(self):
        for _ in range(20):
            pw = passgen.password(60, avoid_ambiguous=True)
            for ch in passgen.AMBIGUOUS:
                self.assertNotIn(ch, pw)

    def test_two_calls_differ(self):
        self.assertNotEqual(passgen.password(30), passgen.password(30))

    def test_zero_length_rejected(self):
        with self.assertRaises(ValueError):
            passgen.password(0)

class TestPassphrase(unittest.TestCase):
    def test_word_count(self):
        for n in (2, 4, 7):
            self.assertEqual(len(passgen.passphrase(n).split("-")), n)

    def test_words_come_from_list(self):
        for word in passgen.passphrase(5).split("-"):
            self.assertIn(word.lower(), passgen.WORDS)

    def test_custom_separator(self):
        self.assertEqual(len(passgen.passphrase(3, " ").split(" ")), 3)

    def test_too_few_words(self):
        with self.assertRaises(ValueError):
            passgen.passphrase(1)

class TestUuid(unittest.TestCase):
    def test_v4_format(self):
        self.assertRegex(passgen.uuid4(),
                         r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

    def test_unique(self):
        self.assertEqual(len({passgen.uuid4() for _ in range(200)}), 200)

class TestEntropy(unittest.TestCase):
    def test_longer_is_stronger(self):
        self.assertGreater(passgen.entropy_bits("aB3!" * 8), passgen.entropy_bits("aB3!"))

    def test_wider_alphabet_is_stronger(self):
        self.assertGreater(passgen.entropy_bits("aB3!aaaa"), passgen.entropy_bits("aaaaaaaa"))

    def test_empty_is_zero(self):
        self.assertEqual(passgen.entropy_bits(""), 0.0)

    def test_verdict_bands(self):
        self.assertIn("very weak", passgen.verdict(10))
        self.assertEqual(passgen.verdict(90), "very strong")

if __name__ == "__main__":
    unittest.main(verbosity=1)
