#ifndef CORE_SEEDQR_H
#define CORE_SEEDQR_H

/* Reads a SeedQR back into a mnemonic. It carries the secret, so it never goes through the parser */

#include <stddef.h>
#include <stdint.h>

#define BIP39_WORD_MAX 8
#define BIP39_PASSPHRASE_MAX 64

/* Accepts a standard SeedQR (four digits per word, 12 or 24 words) or a CompactSeedQR (16 or 32 bytes
 * of entropy). Returns the mnemonic's length and writes it NUL-terminated to out, or 0 if the BIP39
 * checksum does not hold */
int seedqr_decode(const uint8_t *payload, size_t len, char *out, size_t cap);

/* 1 if mn is 12, 15, 18, 21 or 24 English BIP39 words, lower case, one space apart, whose checksum
 * holds. Other wordlists are refused, so a typo cannot pass as a mnemonic in another language */
int bip39_mnemonic_ok(const uint8_t *mn, size_t len);

/* Returns the prefix match count and writes up to cap candidates; exact is set when the prefix is a full word. */
size_t bip39_word_prefix(const uint8_t *prefix, size_t len, char out[][BIP39_WORD_MAX + 1], size_t cap, int *exact);

/* Word entry helpers, after Blockstream Jade's: a keyboard offers only letters that continue a word, and the
 * last word can be limited to the ones whose checksum holds. filter, when not NULL, is the list of word
 * indices to choose from (the final words, say) instead of the whole wordlist */

/* The words starting with prefix as indices: returns how many, writes up to cap of them in order, and sets
 * exact when prefix is itself a word */
size_t bip39_word_matches(const uint8_t *prefix, size_t len, const uint16_t *filter, size_t filter_len, uint16_t *out,
                          size_t cap, int *exact);

/* Bit i is set when the letter 'a' + i follows prefix in some word, so a keyboard can disable the rest */
uint32_t bip39_next_letters(const uint8_t *prefix, size_t len, const uint16_t *filter, size_t filter_len);

/* The last words that complete the first words - 1 indices of a 12, 15, 18, 21 or 24 word mnemonic with a
 * valid checksum: 128 for 12 words down to 8 for 24, in wordlist order. Returns how many, or 0 when the
 * length is wrong, an index is out of range or cap is too small */
size_t bip39_final_words(const uint16_t *idx, size_t words, uint16_t *out, size_t cap);

/* Derives a BIP39 seed from a valid English mnemonic and a printable ASCII passphrase of at most 64 bytes. */
int bip39_seed_from_mnemonic(const uint8_t *mn, size_t mn_len, const uint8_t *passphrase, size_t passphrase_len,
                             uint8_t seed[64]);

/* Leading, trailing and repeated whitespace dropped and A-Z lowered, as keyboards add them. Writes at
 * most len bytes to out, which may be in, and returns how many */
size_t bip39_normalize(const uint8_t *in, size_t len, uint8_t *out);

/* The SeedQR for a 12 or 24 word mnemonic: the Standard digits (48 or 96 ASCII bytes), or with compact
 * the CompactSeedQR's raw entropy (16 or 32 bytes). Returns its length, or 0 */
int seedqr_encode(const uint8_t *mn, size_t len, int compact, uint8_t *out, size_t cap);

/* The mnemonic for 16, 20, 24, 28 or 32 bytes of entropy, written NUL-terminated to out. Returns its
 * length, or 0 for another length or too small a buffer */
int bip39_mnemonic_from_entropy(const uint8_t *ent, size_t len, char *out, size_t cap);

/* Dice rolls as the characters 1 to 6, at least 50 for 12 words (129 bits) and 99 for 24 (255.9 bits, the
 * usual count). The entropy is SHA-256 of the rolls, cut to 16 bytes for 12 words */
int bip39_mnemonic_from_dice(const uint8_t *rolls, size_t len, unsigned int words, char *out, size_t cap);

#endif
