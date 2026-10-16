/* Checking a typed mnemonic, against BIP39's reference vectors */
#include <stdio.h>
#include <string.h>
#include "seedqr.h"
#include "sha512.h"
#include "bip39_vectors.h"

static int checks, failures;
#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        checks++;                                                                                                      \
        if (!(cond)) {                                                                                                 \
            failures++;                                                                                                \
            printf("FAIL ");                                                                                           \
            printf(__VA_ARGS__);                                                                                       \
            printf("\n");                                                                                              \
        }                                                                                                              \
    } while (0)

static int ok(const char *mn) {
    return bip39_mnemonic_ok((const uint8_t *)mn, strlen(mn));
}

static void to_hex(const uint8_t *in, char out[129]) {
    for (unsigned int i = 0; i < 64; i++) snprintf(out + 2 * i, 3, "%02x", in[i]);
}

int main(void) {
    for (unsigned int i = 0; i < sizeof(bip39_vectors) / sizeof(bip39_vectors[0]); i++) {
        const char *mn = bip39_vectors[i].mnemonic;
        uint8_t seed[64];
        char hex[129];
        CHECK(ok(mn), "vector %u accepted", i);
        pbkdf2_hmac_sha512((const uint8_t *)mn, strlen(mn), (const uint8_t *)"mnemonicTREZOR", 14, 2048, seed);
        for (unsigned int k = 0; k < 64; k++) snprintf(hex + 2 * k, 3, "%02x", seed[k]);
        CHECK(!strcmp(hex, bip39_vectors[i].seed), "vector %u seed", i);
    }

    {
        char words[3][BIP39_WORD_MAX + 1];
        int exact = 0;
        size_t n = bip39_word_prefix((const uint8_t *)"aban", 4, words, 3, &exact);
        CHECK(n == 1 && !exact && !strcmp(words[0], "abandon"), "unique four-letter prefix");
        n = bip39_word_prefix((const uint8_t *)"act", 3, words, 3, &exact);
        CHECK(n > 1 && exact && !strcmp(words[0], "act"), "exact word can be chosen from a longer prefix");
        n = bip39_word_prefix((const uint8_t *)"qq", 2, words, 3, &exact);
        CHECK(n == 0 && !exact, "unknown prefix has no candidates");
        n = bip39_word_prefix((const uint8_t *)"ab", 2, words, 3, &exact);
        CHECK(n > 3 && !exact && !strcmp(words[0], "abandon") && !strcmp(words[2], "able"),
              "candidate count is not limited by the output capacity");
        n = bip39_word_prefix(NULL, 0, words, 3, &exact);
        CHECK(n == 2048 && !exact && !strcmp(words[0], "abandon"), "empty prefix lists the dictionary");
    }
    {
        static const char *const mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        static const char *const empty_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b"
                                              "389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        static const char *const ascii_seed = "15ba3855cd73c9d3344735848aa8d12f2f56b465ff4c3531f510c2a52462d5b81df63bd7"
                                              "f351ac21cbbf45a6555275cb3949e659956dba52deaa687dae6533a8";
        uint8_t seed[64];
        uint8_t long_ascii[BIP39_PASSPHRASE_MAX + 1];
        char hex[129];
        CHECK(bip39_seed_from_mnemonic((const uint8_t *)mnemonic, strlen(mnemonic), NULL, 0, seed),
              "derive with empty passphrase");
        to_hex(seed, hex);
        CHECK(!strcmp(hex, empty_seed), "published vector with empty passphrase");
        CHECK(bip39_seed_from_mnemonic((const uint8_t *)mnemonic, strlen(mnemonic), (const uint8_t *)"A b!~", 5, seed),
              "derive with printable ASCII passphrase");
        to_hex(seed, hex);
        CHECK(!strcmp(hex, ascii_seed), "ASCII case, spaces and punctuation are preserved");
        CHECK(bip39_seed_from_mnemonic((const uint8_t *)mnemonic, strlen(mnemonic), (const uint8_t *)"TREZOR", 6, seed),
              "derive with reference passphrase");
        to_hex(seed, hex);
        CHECK(!strcmp(hex, bip39_vectors[0].seed), "published vector with TREZOR passphrase");
        for (unsigned int i = 0; i < sizeof(long_ascii); i++) long_ascii[i] = (uint8_t)(0x20 + i % 95);
        CHECK(bip39_seed_from_mnemonic((const uint8_t *)mnemonic, strlen(mnemonic), long_ascii, BIP39_PASSPHRASE_MAX,
                                       seed),
              "64 printable ASCII characters are accepted");
        CHECK(!bip39_seed_from_mnemonic((const uint8_t *)mnemonic, strlen(mnemonic), long_ascii,
                                        BIP39_PASSPHRASE_MAX + 1, seed),
              "passphrase longer than the input limit is refused");
        memset(seed, 0xa5, sizeof(seed));
        CHECK(
            !bip39_seed_from_mnemonic((const uint8_t *)mnemonic, strlen(mnemonic), (const uint8_t *)"bad\x1f", 4, seed),
            "control characters are refused");
        CHECK(seed[0] == 0 && seed[63] == 0, "failed derivation clears the output");
    }

    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"),
          "bad checksum refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abaut"),
          "a word not in the list refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "11 words refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
              "about"),
          "13 words refused");
    CHECK(!ok(" abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "a leading space refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about "),
          "a trailing space refused");
    CHECK(!ok("abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "two spaces refused");
    CHECK(!ok("Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "capitals refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandonx"),
          "a word longer than any in the list refused");
    {
        static const char nul[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                                  "abandon about\0";
        CHECK(!bip39_mnemonic_ok((const uint8_t *)nul, sizeof(nul) - 1), "a word padded with NUL refused");
    }
    CHECK(!bip39_mnemonic_ok((const uint8_t *)"about", 0), "empty refused");
    CHECK(!ok("\xe3\x81\x82\xe3\x81\x84\xe3\x81\x93\xe3\x81\x8f\xe3\x81\x97\xe3\x82\x93"),
          "a non-English word refused");

    /* what a keyboard adds: surrounding and repeated whitespace, and capitals, are normalised away */
    {
        static const char typed[] = " \tAbandon abandon  abandon abandon abandon abandon abandon abandon\nabandon "
                                    "abandon abandon ABOUT\r\n";
        const char *want = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                           "about";
        uint8_t out[sizeof(typed)];
        size_t n = bip39_normalize((const uint8_t *)typed, sizeof(typed) - 1, out);
        CHECK(n == strlen(want) && !memcmp(out, want, n), "normalised to the canonical form");
        CHECK(bip39_normalize((const uint8_t *)" \n ", 3, out) == 0, "only whitespace is empty");
        CHECK(bip39_normalize((const uint8_t *)"caf\xc3\xa9", 5, out) == 5 && !memcmp(out, "caf\xc3\xa9", 5),
              "bytes above ASCII are left alone");
    }

    /* generating: entropy to words, against the same vectors, and dice rolls to words */
    for (unsigned int i = 0; i < sizeof(bip39_vectors) / sizeof(bip39_vectors[0]); i++) {
        uint8_t ent[32];
        char out[256];
        size_t n = strlen(bip39_vectors[i].entropy) / 2;
        for (size_t k = 0; k < n; k++) sscanf(bip39_vectors[i].entropy + 2 * k, "%2hhx", &ent[k]);
        CHECK(bip39_mnemonic_from_entropy(ent, n, out, sizeof(out)) == (int)strlen(bip39_vectors[i].mnemonic) &&
                  !strcmp(out, bip39_vectors[i].mnemonic),
              "vector %u from entropy", i);
    }
    for (unsigned int i = 0; i < sizeof(dice_vectors) / sizeof(dice_vectors[0]); i++) {
        const char *r = dice_vectors[i].rolls;
        unsigned int words = strlen(r) >= 99 ? 24 : 12;
        char out[256];
        CHECK(bip39_mnemonic_from_dice((const uint8_t *)r, strlen(r), words, out, sizeof(out)) > 0 &&
                  !strcmp(out, dice_vectors[i].mnemonic),
              "dice vector %u", i);
    }
    {
        static const uint8_t zero[33];
        static const char rolls[] = "123456123456123456123456123456123456123456123456123456123456123456123456123456"
                                    "123456123456123456123";
        char out[256];
        CHECK(bip39_mnemonic_from_entropy(zero, 20, out, sizeof(out)) > 0, "15 words from 20 bytes");
        CHECK(bip39_mnemonic_from_entropy(zero, 28, out, sizeof(out)) > 0, "21 words from 28 bytes");
        CHECK(!bip39_mnemonic_from_entropy(zero, 0, out, sizeof(out)), "no entropy refused");
        CHECK(!bip39_mnemonic_from_entropy(zero, 15, out, sizeof(out)), "15 bytes refused");
        CHECK(!bip39_mnemonic_from_entropy(zero, 33, out, sizeof(out)), "33 bytes refused");
        memset(out, 0x55, sizeof(out));
        CHECK(!bip39_mnemonic_from_entropy(zero, 32, out, 100), "a small buffer refused");
        {
            int clean = 1;
            for (unsigned int k = 0; k < 100; k++)
                clean &= out[k] == 0 || out[k] == 0x55; /* cleared, or never written */
            CHECK(clean, "and none of the words written before it ran out are left");
        }
        CHECK(sizeof(rolls) - 1 == 99, "99 rolls");
        CHECK(bip39_mnemonic_from_dice((const uint8_t *)rolls, 99, 24, out, sizeof(out)) > 0, "99 rolls, 24 words");
        CHECK(!bip39_mnemonic_from_dice((const uint8_t *)rolls, 98, 24, out, sizeof(out)), "98 rolls for 24 refused");
        CHECK(bip39_mnemonic_from_dice((const uint8_t *)rolls, 50, 12, out, sizeof(out)) > 0, "50 rolls, 12 words");
        CHECK(!bip39_mnemonic_from_dice((const uint8_t *)rolls, 49, 12, out, sizeof(out)), "49 rolls for 12 refused");
        CHECK(!bip39_mnemonic_from_dice((const uint8_t *)rolls, 99, 18, out, sizeof(out)), "18 words refused");
        CHECK(!bip39_mnemonic_from_dice((const uint8_t *)"0234561234561234561234561234561234561234561234561234", 52, 12,
                                        out, sizeof(out)),
              "a 0 refused");
        CHECK(!bip39_mnemonic_from_dice((const uint8_t *)"7234561234561234561234561234561234561234561234561234", 52, 12,
                                        out, sizeof(out)),
              "a 7 refused");
    }

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
