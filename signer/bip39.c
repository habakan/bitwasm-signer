/* BIP39 English mnemonics: parsing, checksums, seeds, and the word entry helpers. Every mnemonic that
 * comes in or goes out has its checksum verified */
#include "bip39.h"
#include <string.h>
#include "bip39_words.h"
#include "sha256.h"
#include "sha512.h"
#include "wipe.h"

static void sha256_of(const uint8_t *p, size_t n, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, p, n);
    sha256_final(&c, out);
    wipe(&c, sizeof(c));
}

unsigned int bip39_indices_entropy(const uint16_t *idx, unsigned int n, uint8_t ent[32]) {
    unsigned int ent_bits = n * 11 - n / 3;
    memset(ent, 0, 32);
    for (unsigned int i = 0; i < ent_bits; i++)
        ent[i / 8] |= (uint8_t)((idx[i / 11] >> (10 - i % 11) & 1) << (7 - i % 8));
    return ent_bits / 8;
}

/* The checksum bits after the entropy, against SHA-256 of it */
static int checksum_ok(const uint16_t *idx, unsigned int n) {
    uint8_t ent[32], hash[32];
    unsigned int ent_len = bip39_indices_entropy(idx, n, ent), ent_bits = ent_len * 8, cs_bits = n / 3;
    int ok = 1;

    sha256_of(ent, ent_len, hash);
    for (unsigned int i = 0; i < cs_bits; i++) {
        unsigned int want = hash[0] >> (7 - i) & 1, got = idx[n - 1] >> (10 - (ent_bits % 11 + i)) & 1;
        ok &= want == got;
    }
    wipe(ent, sizeof(ent));
    wipe(hash, sizeof(hash));
    return ok;
}

int bip39_mnemonic_from_indices(const uint16_t *idx, unsigned int n, char *out, size_t cap) {
    size_t len = 0;

    if (!checksum_ok(idx, n)) return 0;
    for (unsigned int i = 0; i < n; i++) {
        size_t w = strnlen(bip39_words[idx[i]], 8);
        if (len + w + 1 >= cap) return wipe(out, len), 0;
        if (i) out[len++] = ' ';
        memcpy(out + len, bip39_words[idx[i]], w);
        len += w;
    }
    out[len] = 0;
    return (int)len;
}

/* The list is sorted, and NUL padding sorts before any letter, so comparing all eight bytes keeps it
 * sorted. Only a-z is let through, so a word padded with NUL cannot match a shorter one */
static int word_index(const uint8_t *w, size_t len) {
    char key[8] = {0};
    int lo = 0, hi = 2047, found = -1;
    for (size_t i = 0; i < len && len <= 8; i++) {
        if (w[i] < 'a' || w[i] > 'z') hi = -1;
        key[i] = (char)w[i];
    }
    while (len && len <= 8 && found < 0 && lo <= hi) {
        int mid = (lo + hi) / 2, c = memcmp(key, bip39_words[mid], 8);
        if (!c) found = mid;
        else if (c < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    wipe(key, sizeof(key));
    return found;
}

static int prefix_ok(const uint8_t *prefix, size_t len) {
    if (len > BIP39_WORD_MAX || (len && !prefix)) return 0;
    for (size_t i = 0; i < len; i++)
        if (prefix[i] < 'a' || prefix[i] > 'z') return 0;
    return 1;
}

/* The words starting with prefix are a run in the sorted list: its first index, and its length */
static size_t prefix_range(const uint8_t *prefix, size_t len, unsigned int *first) {
    unsigned int lo = 0, hi = 2048, end;
    while (lo < hi) {
        unsigned int mid = (lo + hi) / 2;
        if (len && memcmp(bip39_words[mid], prefix, len) < 0) lo = mid + 1;
        else hi = mid;
    }
    for (end = lo; end < 2048 && (!len || !memcmp(bip39_words[end], prefix, len)); end++) continue;
    *first = lo;
    return end - lo;
}

size_t bip39_word_prefix(const uint8_t *prefix, size_t len, char out[][BIP39_WORD_MAX + 1], size_t cap, int *exact) {
    unsigned int first = 0;
    size_t found;

    if (exact) *exact = 0;
    if (!prefix_ok(prefix, len)) return 0;
    found = prefix_range(prefix, len, &first);
    for (size_t i = 0; i < found; i++) {
        size_t word_len = strnlen(bip39_words[first + i], BIP39_WORD_MAX);
        if (word_len == len && exact) *exact = 1;
        if (out && i < cap) {
            memcpy(out[i], bip39_words[first + i], word_len);
            out[i][word_len] = 0;
        }
    }
    return found;
}

size_t bip39_word_matches(const uint8_t *prefix, size_t len, const uint16_t *filter, size_t filter_len, uint16_t *out,
                          size_t cap, int *exact) {
    unsigned int first = 0;
    size_t found = 0, n;

    if (exact) *exact = 0;
    if (!prefix_ok(prefix, len)) return 0;
    n = filter ? filter_len : prefix_range(prefix, len, &first);
    for (size_t i = 0; i < n; i++) {
        unsigned int w = filter ? filter[i] : first + (unsigned int)i;
        if (w > 2047 || (len && memcmp(bip39_words[w], prefix, len))) continue;
        if (exact && strnlen(bip39_words[w], BIP39_WORD_MAX) == len) *exact = 1;
        if (out && found < cap) out[found] = (uint16_t)w;
        found++;
    }
    return found;
}

uint32_t bip39_next_letters(const uint8_t *prefix, size_t len, const uint16_t *filter, size_t filter_len) {
    unsigned int first = 0;
    uint32_t mask = 0;
    size_t n;

    if (!prefix_ok(prefix, len) || len >= BIP39_WORD_MAX) return 0;
    n = filter ? filter_len : prefix_range(prefix, len, &first);
    for (size_t i = 0; i < n; i++) {
        unsigned int w = filter ? filter[i] : first + (unsigned int)i;
        if (w > 2047 || (len && memcmp(bip39_words[w], prefix, len)) || !bip39_words[w][len]) continue;
        mask |= 1u << (bip39_words[w][len] - 'a');
    }
    return mask;
}

size_t bip39_normalize(const uint8_t *in, size_t len, uint8_t *out) {
    size_t n = 0;
    int gap = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            gap = n > 0;
            continue;
        }
        if (gap) out[n++] = ' ', gap = 0;
        out[n++] = c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32) : c;
    }
    return n;
}

unsigned int bip39_mnemonic_indices(const uint8_t *mn, size_t len, uint16_t idx[24]) {
    unsigned int n = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && mn[i] != ' ') continue;
        int v = n < 24 ? word_index(mn + start, i - start) : -1;
        if (v < 0) return 0;
        idx[n++] = (uint16_t)v;
        start = i + 1;
    }
    return n % 3 == 0 && n >= 12 && checksum_ok(idx, n) ? n : 0;
}

int bip39_mnemonic_ok(const uint8_t *mn, size_t len) {
    uint16_t idx[24];
    int ok = bip39_mnemonic_indices(mn, len, idx) != 0;
    wipe(idx, sizeof(idx));
    return ok;
}

int bip39_seed_from_mnemonic(const uint8_t *mn, size_t mn_len, const uint8_t *passphrase, size_t passphrase_len,
                             uint8_t seed[64]) {
    uint8_t salt[8 + BIP39_PASSPHRASE_MAX];

    if (!seed) return 0;
    wipe(seed, 64);
    if (!mn || passphrase_len > BIP39_PASSPHRASE_MAX || (passphrase_len && !passphrase) ||
        !bip39_mnemonic_ok(mn, mn_len))
        return 0;
    for (size_t i = 0; i < passphrase_len; i++)
        if (passphrase[i] < 0x20 || passphrase[i] > 0x7e) return 0;
    memcpy(salt, "mnemonic", 8);
    if (passphrase_len) memcpy(salt + 8, passphrase, passphrase_len);
    pbkdf2_hmac_sha512(mn, mn_len, salt, 8 + passphrase_len, 2048, seed);
    wipe(salt, sizeof(salt));
    return 1;
}

unsigned int bip39_entropy_indices(const uint8_t *ent, size_t len, uint16_t idx[24]) {
    uint8_t hash[32];
    unsigned int ent_bits = (unsigned int)len * 8, n = ent_bits / 32 * 3;
    sha256_of(ent, len, hash);
    for (unsigned int i = 0; i < n; i++) {
        unsigned int v = 0;
        for (unsigned int k = 0; k < 11; k++) {
            unsigned int b = i * 11 + k;
            v = v << 1 | (b < ent_bits ? ent[b / 8] >> (7 - b % 8) & 1 : hash[0] >> (7 - (b - ent_bits)) & 1);
        }
        idx[i] = (uint16_t)v;
    }
    wipe(hash, sizeof(hash));
    return n;
}

int bip39_mnemonic_from_entropy(const uint8_t *ent, size_t len, char *out, size_t cap) {
    uint16_t idx[24];
    int r;
    if (len < 16 || len > 32 || len % 4) return 0;
    r = bip39_mnemonic_from_indices(idx, bip39_entropy_indices(ent, len, idx), out, cap);
    wipe(idx, sizeof(idx));
    return r;
}

int bip39_mnemonic_from_dice(const uint8_t *rolls, size_t len, unsigned int words, char *out, size_t cap) {
    uint8_t hash[32];
    int r;
    if ((words != 12 || len < 50) && (words != 24 || len < 99)) return 0;
    for (size_t i = 0; i < len; i++)
        if (rolls[i] < '1' || rolls[i] > '6') return 0;
    sha256_of(rolls, len, hash);
    r = bip39_mnemonic_from_entropy(hash, words == 12 ? 16 : 32, out, cap);
    wipe(hash, sizeof(hash));
    return r;
}

/* Every value of the last word's entropy bits, each with the checksum it needs */
size_t bip39_final_words(const uint16_t *idx, size_t words, uint16_t *out, size_t cap) {
    uint16_t all[24];
    uint8_t ent[32], hash[32];
    unsigned int cs_bits = (unsigned int)words / 3, n = 1u << (11 - cs_bits);

    if (!idx || !out || words < 12 || words > 24 || words % 3 || cap < n) return 0;
    for (size_t i = 0; i + 1 < words; i++) {
        if (idx[i] > 2047) return wipe(all, sizeof(all)), 0;
        all[i] = idx[i];
    }
    for (unsigned int e = 0; e < n; e++) {
        all[words - 1] = (uint16_t)(e << cs_bits);
        sha256_of(ent, bip39_indices_entropy(all, (unsigned int)words, ent), hash);
        out[e] = (uint16_t)(e << cs_bits | (unsigned int)hash[0] >> (8 - cs_bits));
    }
    wipe(all, sizeof(all));
    wipe(ent, sizeof(ent));
    wipe(hash, sizeof(hash));
    return n;
}
