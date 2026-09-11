import random
import Q1  # your coursework cipher

MASK64 = Q1.MASK64

# --- Oracle wrappers -------------------------------------------------


def real_cipher_oracle_factory(secret_key):
    """
    Returns an oracle O(P) = Encrypt_ECB(P, secret_key)
    This models the 'real world' in the security game.
    """

    def oracle(P):
        P &= MASK64
        return Q1.Encrypt_ECB(P, secret_key)

    return oracle


def random_permutation_oracle_factory():
    """
    Returns an oracle O(P) that behaves like a random permutation on 64-bit blocks.
    This models the 'ideal world' (random cipher).
    """
    table = {}

    def oracle(P):
        P &= MASK64
        if P not in table:
            table[P] = random.getrandbits(64)
        return table[P]

    return oracle


# --- Differential distinguisher -------------------------------------


def dc_distinguisher(oracle, num_trials=4000, delta=1, threshold=0.015):
    """
    Run the differential distinguisher against a black-box oracle.

    - oracle: function taking a 64-bit integer P and returning a 64-bit integer C
    - num_trials: how many (P, P^delta) pairs to test
    - delta: input difference (we use 0x1)
    - threshold: decision boundary between 'real cipher' and 'random'

    Returns: (guess, frequency, hits)
        guess = 1 if we think 'real cipher', 0 if 'random permutation'
        frequency = hits / num_trials
        hits = number of times low byte of deltaC == 0x01
    """
    hits = 0
    for _ in range(num_trials):
        P = random.getrandbits(64)
        P2 = (P ^ delta) & MASK64

        C1 = oracle(P)
        C2 = oracle(P2)

        deltaC_low = (C1 ^ C2) & 0xFF
        if deltaC_low == 0x01:
            hits += 1

    freq = hits / num_trials
    guess = 1 if freq > threshold else 0
    return guess, freq, hits


# --- Demo: measure advantage ----------------------------------------


def demo():
    NUM_TRIALS = 4000
    DELTA = 0x01
    THRESH = 0.015

    # Real cipher world
    secret_key = random.getrandbits(64)
    real_oracle = real_cipher_oracle_factory(secret_key)
    guess_real, freq_real, hits_real = dc_distinguisher(
        real_oracle, num_trials=NUM_TRIALS, delta=DELTA, threshold=THRESH
    )
    print("[Real cipher world]")
    print(f"  Secret key      : {secret_key:016x}")
    print(f"  Hits            : {hits_real}/{NUM_TRIALS}")
    print(f"  Hit frequency   : {freq_real:.4f}")
    print(f"  Distinguisher guess (1=real,0=random): {guess_real}")
    print()

    # Random permutation world
    rand_oracle = random_permutation_oracle_factory()
    guess_rand, freq_rand, hits_rand = dc_distinguisher(
        rand_oracle, num_trials=NUM_TRIALS, delta=DELTA, threshold=THRESH
    )
    print("[Random permutation world]")
    print(f"  Hits            : {hits_rand}/{NUM_TRIALS}")
    print(f"  Hit frequency   : {freq_rand:.4f}")
    print(f"  Distinguisher guess (1=real,0=random): {guess_rand}")


if __name__ == "__main__":
    demo()
