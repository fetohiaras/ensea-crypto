import re
from collections import Counter

#!/usr/bin/env python3
# crackvigenere.py
# Calculate and print Index of Coincidence contributions per letter for Exo3.txt


def coincidence_indexes_from_file(path='Exo3.txt'):
    """
    Read file, keep only A-Z letters, compute per-letter IoC contributions and total IoC.
    Returns (ioc_per_letter_dict, total_ioc, counts, N)
    """
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    return coincidence_indexes_from_text(text)


def coincidence_indexes_from_text(text):
    """
    Compute per-letter Index of Coincidence contributions and total IoC from a text string.
    Returns (ioc_per_letter_dict, total_ioc, counts, N).
    """
    letters = re.sub(r'[^A-Za-z]', '', text).upper()
    N = len(letters)
    if N < 2:
        # return zeros/empty structures but keep function signature
        return {chr(c): 0.0 for c in range(65, 91)}, 0.0, Counter(), N

    counts = Counter(letters)
    denom = N * (N - 1)
    ioc_per_letter = {}
    for code in range(65, 91):  # A-Z
        L = chr(code)
        f_i = counts.get(L, 0)
        contrib = (f_i * (f_i - 1)) / denom
        ioc_per_letter[L] = contrib

    total_ioc = sum(ioc_per_letter.values())
    return ioc_per_letter, total_ioc, counts, N


def friedman_test_from_text(text, max_k=20, target=0.0778, tol=0.001, verbose=True):
    """
    Perform a Friedman-style test to estimate key length k.

    For each k from 1..max_k, split the cleaned text into k subsequences
    by taking every k-th letter starting at offsets 0..k-1, compute the
    Index of Coincidence (IoC) for each subsequence, and report the average
    IoC across the k subsequences.

    Stops early when the average IoC is within `tol` of `target` (default
    target 0.0778). Returns a dict mapping k -> (avg_ioc, [ioc_per_subseq]).
    """
    letters = re.sub(r'[^A-Za-z]', '', text).upper()
    N = len(letters)
    results = {}
    if N == 0:
        if verbose:
            print("No letters found in text.")
        return results

    for k in range(1, min(max_k, max(1, N)) + 1):
        iocs = []
        for offset in range(k):
            subseq = letters[offset::k]
            n = len(subseq)
            if n < 2:
                ioc = 0.0
            else:
                counts = Counter(subseq)
                denom = n * (n - 1)
                ioc = sum((f * (f - 1)) / denom for f in counts.values())
            iocs.append(ioc)

        avg_ioc = sum(iocs) / len(iocs)
        results[k] = (avg_ioc, iocs)
        if verbose:
            iocs_str = ", ".join(f"{v:.6f}" for v in iocs)
            print(f"k={k}: avg IoC={avg_ioc:.6f} | per-subseq IoC=[{iocs_str}]")

        if abs(avg_ioc - target) <= tol:
            if verbose:
                print(f"Stopping: avg IoC {avg_ioc:.6f} within tol {tol} of target {target}")
            break

    return results


def friedman_test_from_file(path='Exo3.txt', **kwargs):
    """Run `friedman_test_from_text` on the contents of `path`.

    Any kwargs are forwarded to `friedman_test_from_text` (e.g., max_k,
    target, tol, verbose).
    """
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    return friedman_test_from_text(text, **kwargs)


# Typical French letter frequency (percent). Source: common frequency tables (approx.)
FRENCH_FREQ_PCT = {
    'A':7.636, 'B':0.901, 'C':3.260, 'D':3.669, 'E':14.715, 'F':1.066,
    'G':0.866, 'H':0.737, 'I':7.529, 'J':0.613, 'K':0.049, 'L':5.456,
    'M':2.968, 'N':7.095, 'O':5.378, 'P':3.021, 'Q':1.362, 'R':6.553,
    'S':7.948, 'T':7.244, 'U':6.311, 'V':1.838, 'W':0.074, 'X':0.427,
    'Y':0.128, 'Z':0.326
}


def _clean_text_letters(text):
    return re.sub(r'[^A-Za-z]', '', text).upper()


def _shift_counts_to_plaintext_obs(counts, shift, n):
    """Given counts of ciphertext letters in a subsequence, return frequency
    percentages of letters after applying a candidate key-letter shift (i.e.
    shift=0 means 'A' key — no shift). The returned mapping is pct per A-Z.
    """
    # counts: Counter of ciphertext letters (A-Z) in this subsequence
    freqs = {chr(c): 0.0 for c in range(65, 91)}
    if n == 0:
        return freqs
    # For each ciphertext letter C, the plaintext letter would be P = (C - shift)
    for c, cnt in counts.items():
        c_idx = ord(c) - 65
        p_idx = (c_idx - shift) % 26
        p_letter = chr(p_idx + 65)
        freqs[p_letter] += 100.0 * cnt / n
    return freqs


def _score_against_french(freqs_pct, french_pct):
    """Return a similarity score between observed percentages and french percentages.
    Higher is better. We'll use simple dot-product (sum obs_pct * french_pct).
    Both inputs are dicts keyed by A-Z with percent values.
    """
    score = 0.0
    for L in (chr(c) for c in range(65, 91)):
        score += freqs_pct.get(L, 0.0) * french_pct.get(L, 0.0)
    return score


def crack_vigenere_by_freq_from_text(text, k, french_freq_pct=None, top_n=1):
    """
    For known key length k, attempt to recover key letters by frequency analysis.

    For each key position i in 0..k-1:
      - take subsequence letters[i::k]
      - compute counts
      - for each candidate shift (0..25) compute plaintext-frequency after shifting
        and score it against `french_freq_pct` using dot-product similarity
      - collect best `top_n` shifts (highest scores) and return them

    Returns a list of length k where each element is a list of tuples
    (shift_int, shift_letter, score, freqs_pct_after_shift).
    shift_int: 0..25 where 0 -> 'A' (no shift), 1 -> 'B', etc. shift means the key
    letter that would decrypt ciphertext: P = (C - shift).
    """
    if french_freq_pct is None:
        french_freq_pct = FRENCH_FREQ_PCT

    letters = _clean_text_letters(text)
    N = len(letters)
    results = []
    for offset in range(k):
        subseq = letters[offset::k]
        n = len(subseq)
        counts = Counter(subseq)

        # Evaluate each possible shift
        candidates = []
        for shift in range(26):
            freqs_after = _shift_counts_to_plaintext_obs(counts, shift, n)
            score = _score_against_french(freqs_after, french_freq_pct)
            # shift_letter is key letter: 'A' means shift 0, 'B' shift 1, etc.
            shift_letter = chr(65 + shift)
            candidates.append((shift, shift_letter, score, freqs_after))

        # sort descending by score
        candidates.sort(key=lambda x: x[2], reverse=True)
        results.append(candidates[:top_n])

    return results


def crack_vigenere_by_freq_from_file(path='Exo3.txt', k=7, **kwargs):
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    return crack_vigenere_by_freq_from_text(text, k, **kwargs)


def vigenere_decrypt(text, key):
    """Decrypt `text` with Vigenère `key`.

    Non-letter characters are preserved; case is preserved.
    `key` is expected to be alphabetic; it's used cyclically.
    """
    if not key:
        return text
    key_up = ''.join([c for c in key.upper() if c.isalpha()])
    if not key_up:
        return text
    klen = len(key_up)
    out = []
    ki = 0
    for ch in text:
        if 'A' <= ch <= 'Z' or 'a' <= ch <= 'z':
            is_upper = ch.isupper()
            base = 65 if is_upper else 97
            c_idx = ord(ch.upper()) - 65
            shift = ord(key_up[ki % klen]) - 65
            p_idx = (c_idx - shift) % 26
            p_char = chr(p_idx + base)
            out.append(p_char)
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)


def decrypt_file(path='Exo3.txt', key=''):
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    return vigenere_decrypt(text, key)

if __name__ == "__main__":
    coincidence_indexes_from_file('Exo3.txt')