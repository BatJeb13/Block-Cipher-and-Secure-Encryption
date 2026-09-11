import random
import Q1

MASK64 = (1 << 64) - 1

# Parameters for the distinguisher as described in the writeup
NUM_TRIALS = 4000
DELTA = 0x0000000000000001
THRESH = 0.015


# Both return their respective oraceles
def real_cipher_oracle_factory(secret_key):
    def oracle(P):
        P &= MASK64
        return Q1.Encrypt_ECB(P, secret_key)

    return oracle


def random_permutation_oracle_factory():
    table = {}

    def oracle(P):
        P &= MASK64
        if P not in table:
            table[P] = random.getrandbits(64)
        return table[P]

    return oracle


# How it works:
# For each trial, we pick a random plaintext P1, and compute P2 = P1 ^ delta
# We query the oracle on both P1 and P2 to get ciphertexts C1 and C2
# We then check if the low byte of (C1 ^ C2) is equal to 0x01
# We count how many times this happens (hits)
# After all trials, we compute the frequency of hits
# If the frequency exceeds the threshold, we guess it's the real cipher (1), else random (0)
def dc_distinguisher(oracle, num_trials, delta, threshold):
    hits = 0

    for _ in range(num_trials):
        P1 = random.getrandbits(64)
        P2 = (P1 ^ delta) & MASK64

        C1 = oracle(P1)
        C2 = oracle(P2)

        # Low byte of ciphertext difference
        if ((C1 ^ C2) & 0xFF) == 0x01:
            hits += 1

    freq = hits / num_trials
    guess = 1 if freq > threshold else 0
    return guess, freq, hits


# Demo
print("Demo")
# Real cipher world
secret_key = random.getrandbits(64) & MASK64
real_oracle = real_cipher_oracle_factory(secret_key)

guess_real, freq_real, hits_real = dc_distinguisher(
    real_oracle, NUM_TRIALS, DELTA, THRESH
)

print("Real cipher world:")
print(f"Secret key: {secret_key:016x}")
print(f"Hits: {hits_real}/{NUM_TRIALS}")
print(f"Hit frequency: {freq_real:.4f}")
print(f"Distinguisher guess (1=real,0=random): {guess_real}\n")
print(f"Guess correct? {guess_real == 1}\n")

# Random permutation world
rand_oracle = random_permutation_oracle_factory()

guess_rand, freq_rand, hits_rand = dc_distinguisher(
    rand_oracle, NUM_TRIALS, DELTA, THRESH
)

print("Random permutation world:")
print(f"Hits: {hits_rand}/{NUM_TRIALS}")
print(f"Hit frequency: {freq_rand:.4f}")
print(f"Distinguisher guess (1=real,0=random): {guess_rand}\n")
print(f"Guess correct? {guess_rand == 0}\n")
