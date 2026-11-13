#!/usr/bin/env python3
"""
passgen - generate passwords, passphrases and UUIDs with the system CSPRNG.

Usage:
    python passgen.py                     4 passwords, 20 characters
    python passgen.py --length 32 --count 3
    python passgen.py --passphrase --words 5
    python passgen.py --uuid
    python passgen.py --check "hunter2"   estimate the strength of a password

Stdlib only. Uses secrets, never random.
"""

import argparse
import math
import re
import secrets
import sys

APP = "passgen"
VERSION = "1.0"

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = LOWER.upper()
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = "Il1O0o|`'\""

# 200 short, unambiguous English words. Enough for ~7.6 bits per word.
WORDS = """acid acorn actor adapt adult agent alarm album alert alley almond amber anchor angle
animal answer apple apron arch archer arctic arena argue armor arrow artist atlas atom attic
autumn avenue avoid awake axis bacon badge bagel baker bamboo banjo barley basket baton beach
beacon beam bean beard beaver bell belt bench berry bike birch bird bishop bison blade blanket
blaze blend bloom board boat bolt bonus boot bottle bounce box braid branch brave bread brick
bridge bright broom brush bubble bucket buffalo bugle bulb bundle burrow bus butter button cabin
cable cactus camel camera candle candy canoe canvas canyon carbon cargo carpet carrot cart
castle cedar cell chain chalk charm cherry chess chest chicken chief child chimney chord cider
cinnamon circle citrus city clamp clay cliff cloak clock cloud clover coach coast cobalt cocoa
coil comet compass copper coral cork corner cotton cougar county cover crane crater crayon
creek crest cricket crimson crisp crop crown crystal cube curtain cycle daisy dance dawn delta
denim desert desk dew diamond digital dinner disc dock dolphin dome donkey dot dove dragon
drum duck dune dusk eagle earth easel east echo eclipse edge elbow elder ember emerald engine
envelope equal era essay ether fabric falcon family farm feather fence fern ferry fiber field
fig film finch firefish flag flame flash fleet flint flock flute foam fog foil forest forge
fork fossil fountain fox frame frost fruit fuel funnel fur galaxy garden garlic gate gauge
gear gecko gem ginger glacier glass globe glove gold goose gorge grain grape grass gravel
green grid grove guitar gull habit hammer harbor harp harvest hawk hazel heart hedge helm
heron hill hinge hive hollow honey hoof horizon horse hotel humble hunter iceberg igloo index
indigo inlet insect iris iron island ivory ivy jacket jade jaguar jar jasmine jasper jelly
jewel jockey journal judge jug juice jungle juniper jury kaleidoscope kayak kettle key kite
kitten knee knot koala ladder lagoon lake lamp lantern lark laser latch lava lawn leaf ledge
lemon lens level lily lime linen lion lizard llama lobby lobe lock log loop lotus lounge
lunar lute lynx machine magnet magpie mango maple marble march marsh mask mast meadow medal
melon mesa metal meteor mint mirror mist mitten model mole monarch moon moose moss motel
moth motion mound mouse muffin mulberry mural music mustang nectar needle nest nickel night
north novel nut oak oasis ocean olive onion opal opera orange orbit orchid otter owl oxide
oyster paddle page palm panda panel panther paper parade parrot pasta patio pattern peach
pearl pebble pecan pedal pelican pencil penguin pepper petal piano pickle pier pigeon pillar
pine pink pioneer pipe pistachio pixel planet plank plum pocket poem polar pond pony poplar
poppy porch portal poster prairie prism pulse pumpkin puzzle python quail quartz queen quill
rabbit radar raft rail rainbow raven ravine ray reed reef relay ribbon rice ridge rifle ring
ripple river road robin rocket rodeo roof root rope rose rover royal ruby rudder rug ruler
rust saddle saffron sage sail salmon sand sapphire satin scale scarf school scout scroll
seal season seed sesame shade shadow shell shield shore shovel silk silver sketch sky slate
sleigh slide slope smoke snail snow soap socket solar solid sonnet sound south sparrow spice
spider spire spirit splash spring spruce square squash squid stable stack star steam steel
stem step stork storm stove stream street stripe studio sugar summit sun swan sweet swift
switch sword table talon tapir tea teal temple tent thistle thorn thread thunder tide tiger
timber tin toad toast tomato topaz torch tower trail train tree tulip tunnel turtle twig
umbrella union urchin valley vanilla vapor vase velvet vertex vessel vine violet vision vivid
vortex voyage wagon walnut walrus wand wasp watch water wave wax wheat whisker whisper willow
window winter wolf wood wool wren yarn yellow yield zebra zephyr zinc zone""".split()


def password(length=20, symbols=True, avoid_ambiguous=False):
    """A random password from the system CSPRNG, one character at a time."""
    alphabet = LOWER + UPPER + DIGITS + (SYMBOLS if symbols else "")
    if avoid_ambiguous:
        alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS)
    if length < 1:
        raise ValueError("length must be at least 1")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def passphrase(words=5, separator="-", capitalise=True):
    """Words chosen by secrets.choice, so the order cannot be predicted."""
    if words < 2:
        raise ValueError("use at least 2 words")
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    if capitalise:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def uuid4():
    import uuid
    return str(uuid.uuid4())


def entropy_bits(text, pool_size=None):
    """
    Rough strength estimate. With no pool given, infer it from the characters used.
    This is a lower bound: a passphrase of dictionary words is stronger than the
    character count suggests, and 'Password1' is weaker than its length suggests.
    """
    if not text:
        return 0.0
    if pool_size is None:
        pool = 0
        if re.search(r"[a-z]", text):
            pool += 26
        if re.search(r"[A-Z]", text):
            pool += 26
        if re.search(r"[0-9]", text):
            pool += 10
        if re.search(r"[^a-zA-Z0-9]", text):
            pool += 32
        pool_size = max(pool, 1)
    return len(text) * math.log2(pool_size)


def verdict(bits):
    if bits < 28:
        return "very weak - guessable in seconds"
    if bits < 40:
        return "weak - fine for nothing important"
    if bits < 60:
        return "fair - acceptable for low-value logins"
    if bits < 80:
        return "strong"
    return "very strong"


def main(argv=None):
    p = argparse.ArgumentParser(prog=APP, description="Generate passwords, passphrases and UUIDs.")
    p.add_argument("--length", type=int, default=20, help="password length (default 20)")
    p.add_argument("--count", type=int, default=4, help="how many to print (default 4)")
    p.add_argument("--no-symbols", action="store_true", help="letters and digits only")
    p.add_argument("--avoid-ambiguous", action="store_true",
                   help="drop characters that look alike: I l 1 O 0 o")
    p.add_argument("--passphrase", action="store_true", help="generate word-based passphrases")
    p.add_argument("--words", type=int, default=5, help="words per passphrase (default 5)")
    p.add_argument("--separator", default="-", help="passphrase separator (default -)")
    p.add_argument("--uuid", action="store_true", help="print UUID v4 values instead")
    p.add_argument("--check", metavar="TEXT", help="estimate the strength of a password")
    p.add_argument("--version", action="version", version=f"{APP} {VERSION}")
    args = p.parse_args(argv)

    if args.check is not None:
        bits = entropy_bits(args.check)
        print(f"\n  {APP} - strength check\n")
        print(f"  length : {len(args.check)} characters")
        print(f"  entropy: about {bits:.0f} bits")
        print(f"  verdict: {verdict(bits)}")
        print("\n  This is a rough lower bound. A reused password is weak no matter what")
        print("  this says, and a five-word passphrase is stronger than its bit count.")
        return 0

    if args.uuid:
        for _ in range(args.count):
            print(uuid4())
        return 0

    if args.passphrase:
        for _ in range(args.count):
            print(passphrase(args.words, args.separator))
        print(f"\n  {args.words} words from a {len(WORDS)}-word list, chosen by secrets.")
        return 0

    for _ in range(args.count):
        print(password(args.length, not args.no_symbols, args.avoid_ambiguous))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as exc:
        print(f"{APP}: {exc}", file=sys.stderr)
        sys.exit(2)
