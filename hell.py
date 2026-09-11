"""
Q6_differential_ecb.py

Differential cryptanalysis on the S-box used in the COMP3731 Feistel cipher.

What this script does:
  1. Hard-codes the S-box from the coursework.
  2. Builds the full 256 x 256 differential distribution table (DDT).
  3. Prints the top input/output differences with the highest probability.
  4. Picks one good differential (d_in, d_out) and empirically verifies it
     using random x pairs:
         S(x) ^ S(x ^ d_in) == d_out
"""

import random

# ===== Constants =====
MASK8 = 0xFF

# ===== Hard-coded S-box (same as in your Q1) =====
SBOX = [
    142,
    79,
    87,
    120,
    121,
    106,
    107,
    92,
    93,
    80,
    81,
    114,
    115,
    148,
    101,
    134,
    158,
    95,
    103,
    136,
    137,
    122,
    123,
    108,
    109,
    96,
    97,
    130,
    131,
    164,
    117,
    150,
    174,
    111,
    119,
    152,
    153,
    138,
    139,
    124,
    125,
    112,
    113,
    146,
    147,
    180,
    133,
    166,
    154,
    155,
    140,
    141,
    128,
    129,
    162,
    163,
    196,
    149,
    182,
    190,
    127,
    135,
    168,
    169,
    198,
    206,
    143,
    151,
    184,
    185,
    170,
    171,
    156,
    157,
    144,
    145,
    178,
    179,
    212,
    165,
    214,
    222,
    159,
    167,
    200,
    201,
    186,
    187,
    172,
    173,
    160,
    161,
    194,
    195,
    228,
    181,
    216,
    217,
    202,
    203,
    188,
    189,
    176,
    177,
    210,
    211,
    244,
    197,
    230,
    238,
    175,
    183,
    232,
    233,
    218,
    219,
    204,
    205,
    192,
    193,
    226,
    227,
    4,
    213,
    246,
    254,
    191,
    199,
    14,
    207,
    215,
    248,
    249,
    234,
    235,
    220,
    221,
    208,
    209,
    242,
    243,
    20,
    229,
    6,
    231,
    8,
    9,
    250,
    251,
    236,
    237,
    224,
    225,
    2,
    3,
    36,
    245,
    22,
    30,
    223,
    247,
    24,
    25,
    10,
    11,
    252,
    253,
    240,
    241,
    18,
    19,
    52,
    5,
    38,
    46,
    239,
    26,
    27,
    12,
    13,
    0,
    1,
    34,
    35,
    68,
    21,
    54,
    62,
    255,
    7,
    40,
    41,
    56,
    57,
    42,
    43,
    28,
    29,
    16,
    17,
    50,
    51,
    84,
    37,
    70,
    78,
    15,
    23,
    72,
    73,
    58,
    59,
    44,
    45,
    32,
    33,
    66,
    67,
    100,
    53,
    86,
    94,
    31,
    39,
    116,
    69,
    102,
    110,
    47,
    55,
    88,
    89,
    74,
    75,
    60,
    61,
    48,
    49,
    82,
    83,
    132,
    85,
    118,
    126,
    63,
    71,
    104,
    105,
    90,
    91,
    76,
    77,
    64,
    65,
    98,
    99,
]


# ===== Core helpers =====


def sbox(x: int) -> int:
    """Apply 8-bit S-box."""
    return SBOX[x & MASK8]


def build_sbox_ddt():
    """
    Build the 256x256 differential distribution table (DDT) for the S-box.

    DDT[din][dout] = number of x such that:
        S(x) ^ S(x ^ din) == dout
    """
    ddt = [[0 for _ in range(256)] for _ in range(256)]

    for din in range(256):
        for x in range(256):
            y1 = sbox(x)
            y2 = sbox(x ^ din)
            dout = y1 ^ y2
            ddt[din][dout] += 1

    return ddt


def get_top_differences(ddt, top_k=10):
    """
    Return the top (din, dout, count, probability) entries
    (excluding din == 0) sorted by probability descending.
    """
    triples = []
    for din in range(1, 256):
        for dout in range(256):
            count = ddt[din][dout]
            if count == 0:
                continue
            p = count / 256.0
            triples.append((din, dout, count, p))

    # Sort by probability then by count
    triples.sort(key=lambda t: (-t[3], -t[2], t[0], t[1]))
    return triples[:top_k]


def print_ddt_summary(ddt, top_k=10):
    print("=== Differential Distribution Table for S-box ===")
    print(f"Table size: 256 x 256 (din, dout)")
    print("For each input difference din, counts are over 256 possible x.\n")

    top = get_top_differences(ddt, top_k=top_k)
    print(f"Top {top_k} input/output differences (by probability):")
    for din, dout, count, p in top:
        print(
            f"  din = 0x{din:02x}, dout = 0x{dout:02x}, "
            f"count = {count:3d}, p = {p:.4f}"
        )


def empirical_check(din: int, dout: int, trials: int = 5000):
    """
    Empirically estimate Pr_x [ S(x) ^ S(x ^ din) == dout ]
    using random x samples.
    """
    hits = 0
    for _ in range(trials):
        x = random.randint(0, 255)
        if sbox(x) ^ sbox(x ^ din) == dout:
            hits += 1
    p_emp = hits / trials
    print("\n=== Empirical check for chosen differential ===")
    print(f"Chosen d_in  = 0x{din:02x}")
    print(f"Chosen d_out = 0x{dout:02x}")
    print(f"Trials       = {trials}")
    print(f"Hits         = {hits}")
    print(f"Empirical p  = {p_emp:.4f}")


# ===== Main driver =====


def main():
    # Step 1: build full DDT
    ddt = build_sbox_ddt()

    # Step 2: print summary + top differentials
    print_ddt_summary(ddt, top_k=10)

    # Step 3: pick the single best non-trivial differential and verify it empirically
    top = get_top_differences(ddt, top_k=1)
    if top:
        din, dout, count, p = top[0]
        print(
            f"\n[+] Using most biased differential for empirical test:"
            f" d_in = 0x{din:02x}, d_out = 0x{dout:02x}, p = {p:.4f}"
        )
        empirical_check(din, dout, trials=5000)
    else:
        print("No non-trivial differentials found (this should never happen).")


if __name__ == "__main__":
    main()
