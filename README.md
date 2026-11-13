# passgen

**Generate passwords, passphrases and UUIDs with the system CSPRNG.** One Python file, no
dependencies, nothing stored anywhere.

```
c2bW$QP&G{rG@/3;Hc3^lkA+
,&={RWLp+9MrKF]]rw8$D;7G
Arrow-Sesame-Scout-Slide

  4 words from a 641-word list, chosen by secrets.
```

## Quick start

```bash
python passgen.py                        # 4 passwords, 20 characters
python passgen.py --length 32 --count 3
python passgen.py --passphrase --words 5
python passgen.py --uuid
python passgen.py --check "hunter2"      # estimate the strength of a password
```

| Flag | What it does |
| --- | --- |
| `--length N` | Password length, default 20 |
| `--count N` | How many to print, default 4 |
| `--no-symbols` | Letters and digits only |
| `--avoid-ambiguous` | Drop `I l 1 O 0 o \|` so you can read it aloud |
| `--passphrase` `--words N` `--separator` | Word-based, from a 641-word list |
| `--uuid` | UUID v4 values |
| `--check TEXT` | Entropy estimate and a plain verdict |

## Why it is built this way

- **`secrets`, never `random`.** `random` is a Mersenne Twister seeded for simulation, not
  security; its output is predictable once you see enough of it. `secrets.choice` reads the
  operating system's CSPRNG. There is a test that fails if anyone swaps it back.
- **One character at a time.** No shuffling a fixed string, no `choice` over a template.
- **Passphrases come from `secrets.choice` per word**, so word order cannot be predicted.
- **Nothing is logged, saved, or sent anywhere.** It prints to stdout and exits.

## What `--check` is honest about

The estimate is a lower bound based on length and character pool. A five-word passphrase is
stronger than its bit count suggests, and `Password1!` is far weaker than its length
suggests because it is a dictionary word plus a pattern. **A reused password is weak no
matter what any meter says** — this tool cannot know that, so it says so here.

## Tests

```bash
python tests/test_passgen.py      # 16 tests
```

Length handling, charset options, ambiguous-character exclusion, uniqueness across calls,
the `secrets` guarantee, passphrase word counts and separators, UUID v4 format and
uniqueness across 200 draws, entropy monotonicity, and the error paths.

## Licence

MIT with Commons Clause. Copyright (c) 2026 Siddhant Neekhra. See [LICENSE.md](LICENSE.md).
