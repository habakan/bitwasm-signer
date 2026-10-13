#include "multisig.h"
#include <string.h>

#define H 0x80000000u

typedef struct {
    const uint8_t *b;
    size_t n, i;
} cbor_r_t;

static int head(cbor_r_t *r, unsigned *major, uint64_t *value) {
    uint8_t first, ai;
    unsigned bytes;
    if (r->i == r->n) return 0;
    first = r->b[r->i++];
    *major = first >> 5;
    ai = first & 31;
    if (ai < 24) {
        *value = ai;
        return 1;
    }
    bytes = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : 0;
    if (!bytes || bytes > r->n - r->i) return 0;
    *value = 0;
    for (unsigned j = 0; j < bytes; j++) *value = *value << 8 | r->b[r->i++];
    return 1;
}

static int uint(cbor_r_t *r, uint64_t *v) {
    unsigned major;
    return head(r, &major, v) && major == 0;
}

static int tag(cbor_r_t *r, uint64_t expected) {
    unsigned major;
    uint64_t v;
    return head(r, &major, &v) && major == 6 && v == expected;
}

static int boolean(cbor_r_t *r, int *v) {
    if (r->i == r->n || (r->b[r->i] != 0xf4 && r->b[r->i] != 0xf5)) return 0;
    *v = r->b[r->i++] == 0xf5;
    return 1;
}

static int bytes(cbor_r_t *r, uint8_t *out, size_t expected) {
    unsigned major;
    uint64_t n;
    if (!head(r, &major, &n) || major != 2 || n != expected || n > r->n - r->i) return 0;
    memcpy(out, r->b + r->i, (size_t)n);
    r->i += (size_t)n;
    return 1;
}

static int skip(cbor_r_t *r, unsigned depth) {
    unsigned major;
    uint64_t n;
    if (depth == 10 || !head(r, &major, &n)) return 0;
    if (major == 2 || major == 3) {
        if (n > r->n - r->i) return 0;
        r->i += (size_t)n;
    } else if (major == 4 || major == 5) {
        if (n > r->n) return 0;
        for (uint64_t i = 0; i < n * (major == 5 ? 2 : 1); i++)
            if (!skip(r, depth + 1)) return 0;
    } else if (major == 6) {
        return skip(r, depth + 1);
    }
    return 1;
}

static int map_start(cbor_r_t *r, uint64_t *n) {
    unsigned major;
    return head(r, &major, n) && major == 5 && *n <= 32;
}

static int map_key(cbor_r_t *r, uint64_t *key, uint32_t *seen) {
    if (!uint(r, key)) return 0;
    if (*key < 32) {
        uint32_t bit = 1u << *key;
        if (*seen & bit) return 0;
        *seen |= bit;
    }
    return 1;
}

static int origin_components(cbor_r_t *r, ms_key_t *key, unsigned *count) {
    unsigned major;
    uint64_t n, index;
    if (!head(r, &major, &n) || major != 4 || n % 2 || n / 2 > MS_MAX_DEPTH) return 0;
    *count = (unsigned)n / 2;
    for (unsigned i = 0; i < *count; i++) {
        int hardened;
        if (!uint(r, &index) || index >= H || !boolean(r, &hardened) || !hardened) return 0;
        key->path[i] = (uint32_t)index | H;
    }
    return 1;
}

static int keypath_origin(cbor_r_t *r, ms_key_t *key) {
    uint64_t n, field, v;
    uint32_t seen = 0;
    unsigned count = 0;
    int have_components = 0, have_fingerprint = 0, have_depth = 0;
    if (!tag(r, 304) || !map_start(r, &n)) return 0;
    for (uint64_t i = 0; i < n; i++) {
        if (!map_key(r, &field, &seen)) return 0;
        if (field == 1) {
            if (!origin_components(r, key, &count)) return 0;
            have_components = 1;
        } else if (field == 2) {
            if (!uint(r, &v) || v > UINT32_MAX) return 0;
            key->fingerprint = (uint32_t)v;
            have_fingerprint = 1;
        } else if (field == 3) {
            if (!uint(r, &v) || v > UINT8_MAX) return 0;
            key->depth = (uint8_t)v;
            have_depth = 1;
        } else if (!skip(r, 0)) return 0;
    }
    if (!have_components || !have_fingerprint || !count || (have_depth && key->depth != count)) return 0;
    key->depth = (uint8_t)count;
    return 1;
}

static int keypath_children(cbor_r_t *r) {
    unsigned major;
    uint64_t n, v;
    uint32_t seen = 0;
    int hardened;
    int have_components = 0;
    if (!tag(r, 304) || !map_start(r, &n)) return 0;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t field;
        if (!map_key(r, &field, &seen)) return 0;
        if (field != 1) {
            if (!skip(r, 0)) return 0;
            continue;
        }
        have_components = 1;
        if (!head(r, &major, &v) || major != 4 || v != 3 || !head(r, &major, &v) || major != 4 || v != 4 ||
            !uint(r, &v) || v != 0 || !boolean(r, &hardened) || hardened || !uint(r, &v) || v != 1 ||
            !boolean(r, &hardened) || hardened || !head(r, &major, &v) || major != 4 || v != 0 ||
            !boolean(r, &hardened) || hardened)
            return 0;
    }
    return have_components;
}

static int coin_info(cbor_r_t *r, int testnet) {
    uint64_t n, field, v;
    uint32_t seen = 0;
    unsigned network = 0;
    if (!tag(r, 305) || !map_start(r, &n)) return 0;
    for (uint64_t i = 0; i < n; i++) {
        if (!map_key(r, &field, &seen)) return 0;
        if (field == 1) {
            if (!uint(r, &v) || v != 0) return 0;
        } else if (field == 2) {
            if (!uint(r, &v) || v > 1) return 0;
            network = (unsigned)v;
        } else if (!skip(r, 0)) return 0;
    }
    return network == (unsigned)testnet;
}

static int hdkey(cbor_r_t *r, int testnet, ms_key_t *key) {
    uint64_t n, field, v;
    uint32_t seen = 0;
    int have_pub = 0, have_chain = 0, have_origin = 0, have_children = 0, have_parent = 0;
    memset(key, 0, sizeof(*key));
    if (!tag(r, 303) || !map_start(r, &n)) return 0;
    key->ser[0] = 0x04;
    key->ser[1] = testnet ? 0x35 : 0x88;
    key->ser[2] = testnet ? 0x87 : 0xb2;
    key->ser[3] = testnet ? 0xcf : 0x1e;
    for (uint64_t i = 0; i < n; i++) {
        if (!map_key(r, &field, &seen)) return 0;
        if (field == 1) {
            int is_master;
            if (!boolean(r, &is_master) || is_master) return 0;
        } else if (field == 2) {
            int is_private;
            if (!boolean(r, &is_private) || is_private) return 0;
        } else if (field == 3) {
            if (!bytes(r, key->ser + 45, 33)) return 0;
            have_pub = 1;
        } else if (field == 4) {
            if (!bytes(r, key->ser + 13, 32)) return 0;
            have_chain = 1;
        } else if (field == 5) {
            if (!coin_info(r, testnet)) return 0;
        } else if (field == 6) {
            if (!keypath_origin(r, key)) return 0;
            have_origin = 1;
        } else if (field == 7) {
            if (!keypath_children(r)) return 0;
            have_children = 1;
        } else if (field == 8) {
            if (!uint(r, &v) || v > UINT32_MAX) return 0;
            key->ser[5] = (uint8_t)(v >> 24);
            key->ser[6] = (uint8_t)(v >> 16);
            key->ser[7] = (uint8_t)(v >> 8);
            key->ser[8] = (uint8_t)v;
            have_parent = 1;
        } else if (!skip(r, 0)) return 0;
    }
    if (!have_pub || !have_chain || !have_origin || !have_children) return 0;
    if (!have_parent) memset(key->ser + 5, 0, 4);
    key->ser[4] = key->depth;
    v = key->path[key->depth - 1];
    key->ser[9] = (uint8_t)(v >> 24);
    key->ser[10] = (uint8_t)(v >> 16);
    key->ser[11] = (uint8_t)(v >> 8);
    key->ser[12] = (uint8_t)v;
    return 1;
}

int ms_cbor_descriptor(const uint8_t *cbor, size_t len, int testnet, char out[MS_DESC_MAX]) {
    cbor_r_t r = {cbor, len, 0};
    ms_wallet_t wallet = {0};
    uint64_t n, field, v, key_count = 0;
    uint32_t seen = 0;
    int have_threshold = 0, have_keys = 0;

    if (!tag(&r, 401) || !tag(&r, 407) || !map_start(&r, &n)) return 0;
    for (uint64_t i = 0; i < n; i++) {
        if (!map_key(&r, &field, &seen)) return 0;
        if (field == 1) {
            if (!uint(&r, &v) || v < 1 || v > MS_MAX_KEYS) return 0;
            wallet.threshold = (uint8_t)v;
            have_threshold = 1;
        } else if (field == 2) {
            unsigned major;
            if (!head(&r, &major, &key_count) || major != 4 || key_count < 2 || key_count > MS_MAX_KEYS) return 0;
            for (unsigned j = 0; j < key_count; j++)
                if (!hdkey(&r, testnet, &wallet.keys[j])) return 0;
            wallet.n = (uint8_t)key_count;
            have_keys = 1;
        } else if (!skip(&r, 0)) return 0;
    }
    if (!have_threshold || !have_keys || wallet.threshold > wallet.n || r.i != r.n) return 0;
    return ms_descriptor(&wallet, testnet, out) != 0;
}
