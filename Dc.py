import random
import statistics
import Q1  # your coursework cipher

MASK64 = Q1.MASK64

# ---------- Oracle factories ----------


def real_cipher_oracle_factory(secret_key):
    """Return oracle O(P) = Encrypt_ECB(P, secret_key)."""

    def oracle(P: int) -> int:
        return Q1.Encrypt_ECB(P & MASK64, secret_key)

    return oracle


def random_permutation_oracle_factory():
    """Return oracle behaving as a random permutation on 64-bit blocks."""
    table = {}

    def oracle(P: int) -> int:
        P &= MASK64
        if P not in table:
            table[P] = random.getrandbits(64)
        return table[P]

    return oracle


# ---------- Core distinguisher ----------


def dc_distinguisher(oracle, num_trials=4000, delta=1, threshold=0.015):
    """
    Differential distinguisher.

    Returns:
        guess  : 1 if 'real cipher', 0 if 'random permutation'
        freq   : hits / num_trials
        hits   : number of times low-byte difference == 0x01
    """
    hits = 0
    for _ in range(num_trials):
        P1 = random.getrandbits(64)
        P2 = (P1 ^ delta) & MASK64

        C1 = oracle(P1)
        C2 = oracle(P2)

        if ((C1 ^ C2) & 0xFF) == 0x01:
            hits += 1

    freq = hits / num_trials
    guess = 1 if freq > threshold else 0
    return guess, freq, hits


def experiment(num_experiments=20, num_trials=4000, delta=1, threshold=0.015):
    """
    Run the distinguisher multiple times in both worlds to estimate
    empirical success probability and the distributions of frequencies.
    """
    print(f"Parameters: N={num_trials}, delta=0x{delta:016x}, threshold={threshold}")

    real_freqs = []
    rand_freqs = []
    real_correct = 0
    rand_correct = 0

    # Real-cipher world
    key = random.getrandbits(64)
    real_oracle = real_cipher_oracle_factory(key)
    print(f"\n[Real cipher world] Key = {key:016x}")
    for i in range(num_experiments):
        guess, freq, hits = dc_distinguisher(real_oracle, num_trials, delta, threshold)
        real_freqs.append(freq)
        if guess == 1:
            real_correct += 1
        print(
            f"  Run {i+1:02d}: hits={hits}/{num_trials}, freq={freq:.4f}, guess={guess}"
        )

    # Random-permutation world
    rand_oracle = random_permutation_oracle_factory()
    print("\n[Random permutation world]")
    for i in range(num_experiments):
        guess, freq, hits = dc_distinguisher(rand_oracle, num_trials, delta, threshold)
        rand_freqs.append(freq)
        if guess == 0:
            rand_correct += 1
        print(
            f"  Run {i+1:02d}: hits={hits}/{num_trials}, freq={freq:.4f}, guess={guess}"
        )

    print("\nSummary statistics:")
    print(
        f"  Real world:   mean freq = {statistics.mean(real_freqs):.4f}, "
        f"stdev = {statistics.pstdev(real_freqs):.4f}, "
        f"correct guesses = {real_correct}/{num_experiments}"
    )
    print(
        f"  Random world: mean freq = {statistics.mean(rand_freqs):.4f}, "
        f"stdev = {statistics.pstdev(rand_freqs):.4f}, "
        f"correct guesses = {rand_correct}/{num_experiments}"
    )


if __name__ == "__main__":
    experiment()
