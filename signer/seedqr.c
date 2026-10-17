/* Reads a SeedQR back into a mnemonic. This carries the secret itself, so it is
 * handled natively and never goes through the parser. The BIP39 checksum is always verified and
 * anything that fails it is refused.
 *
 * Standard SeedQR: four digits per word index (48 digits for 12 words, 96 for 24)
 * CompactSeedQR: the raw entropy (16 or 32 bytes) */
#include "seedqr.h"
#include <string.h>
#include "bip39.h"
#include "wipe.h"

int seedqr_encode(const uint8_t *mn, size_t len, int compact, uint8_t *out, size_t cap) {
    uint16_t idx[24];
    uint8_t ent[32];
    unsigned int n = bip39_mnemonic_indices(mn, len, idx);
    int r = 0;

    if ((n == 12 || n == 24) && !compact && cap >= n * 4) {
        for (unsigned int i = 0; i < n; i++)
            for (unsigned int k = 0, v = idx[i]; k < 4; k++, v /= 10) out[i * 4 + 3 - k] = (uint8_t)('0' + v % 10);
        r = (int)n * 4;
    } else if ((n == 12 || n == 24) && compact && cap >= n * 4 / 3) {
        r = (int)bip39_indices_entropy(idx, n, ent);
        memcpy(out, ent, (size_t)r);
    }
    wipe(idx, sizeof(idx));
    wipe(ent, sizeof(ent));
    return r;
}

int seedqr_decode(const uint8_t *payload, size_t len, char *out, size_t cap) {
    uint16_t idx[24];
    unsigned int n;
    int r;

    if (len == 48 || len == 96) { /* standard SeedQR: four digits per index */
        n = (unsigned int)len / 4;
        for (unsigned int i = 0; i < n; i++) {
            unsigned int v = 0;
            for (unsigned int k = 0; k < 4; k++) {
                uint8_t c = payload[i * 4 + k];
                if (c < '0' || c > '9') return 0;
                v = v * 10 + (unsigned int)(c - '0');
            }
            if (v > 2047) return 0;
            idx[i] = (uint16_t)v;
        }
    } else if (len == 16 || len == 32) { /* CompactSeedQR: the raw entropy */
        n = bip39_entropy_indices(payload, len, idx);
    } else {
        return 0;
    }
    r = bip39_mnemonic_from_indices(idx, n, out, cap);
    wipe(idx, sizeof(idx));
    return r;
}
