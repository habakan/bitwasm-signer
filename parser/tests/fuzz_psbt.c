/* Feeds arbitrary bytes to parser_parse, then exercises what a host would do next.
 * The PSBT comes from whoever shows a QR code, so this is the surface that matters most. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "psbt_parser.h"

/* Named so a crash says which invariant broke; __builtin_trap alone is hard to read */
#define MUST(cond)                                                                                                     \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "broken: %s\n", #cond);                                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char *in = parser_input();
    unsigned int cap = parser_input_cap();
    unsigned int fp;

    /* The first 4 bytes pick the fingerprint, so derivations sometimes match and sometimes do not */
    if (size < 4) return 0;
    fp = (unsigned int)data[0] << 24 | (unsigned int)data[1] << 16 | (unsigned int)data[2] << 8 | data[3];
    data += 4;
    size -= 4;
    if (size > cap) size = cap;
    memcpy(in, data, size);

    if (parser_parse((unsigned int)size, fp) != P_OK) return 0;

    /* A host reads these next; make sure they stay inside the input buffer */
    const plan_t *p = parser_plan();
    MUST(p->magic == PLAN_MAGIC && p->version == PLAN_VERSION);
    MUST(p->n_inputs <= PLAN_MAX_INPUTS && p->n_outputs <= PLAN_MAX_OUTPUTS);
    for (unsigned int i = 0; i < p->n_inputs; i++) {
        unsigned int off = parser_prevtx_off(i), len = parser_prevtx_len(i);
        MUST(!len || (off <= cap && len <= cap - off));
        MUST(p->inputs[i].spk.len <= PLAN_MAX_SPK);
        MUST(p->inputs[i].key.depth <= PLAN_MAX_DEPTH);
    }
    for (unsigned int i = 0; i < PLAN_MAX_INPUTS; i++) {
        const plan_wscript_t *w = &p->wscripts[i];
        MUST(w->len <= PLAN_MAX_WSCRIPT);
        for (unsigned int k = w->len; k < PLAN_MAX_WSCRIPT; k++) MUST(!w->bytes[k]);
        MUST(!w->len || (i < p->n_inputs && p->inputs[i].spk.len == 34 && p->inputs[i].spk.bytes[0] == 0 &&
                         p->inputs[i].spk.bytes[1] == 32 && p->inputs[i].key.depth));
    }
    for (unsigned int i = 0; i < p->n_outputs; i++) {
        MUST(p->outputs[i].spk.len <= PLAN_MAX_SPK);
        MUST(p->outputs[i].key.depth <= PLAN_MAX_DEPTH);
    }

    /* Finalize with empty signatures: reaches the serializer without needing a signer */
    memset(parser_sigs(), 0, sizeof(plan_sig_t) * PLAN_MAX_INPUTS);
    parser_finalize(p->n_inputs);
    return 0;
}
