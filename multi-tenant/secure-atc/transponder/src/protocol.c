/* Wire-format helpers shared by the aircraft transponder. Pure
 * serialisation — no key material is touched here.
 */
#include "shadow_atc.h"

#include <string.h>

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_be64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static uint64_t get_be64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  |  (uint64_t)p[7];
}

/* KnockFrame layout (36 bytes):
 *   token[8] | id_a[8] | nonce_a[16] | version[1] | flags[1] | reserved[2]
 */
shadow_status_t shadow_protocol_pack_knock(uint64_t id_a,
                                           const uint8_t nonce_a[SHADOW_NONCE_LEN],
                                           const uint8_t token[SHADOW_KNOCK_TOKEN_LEN],
                                           uint8_t out[SHADOW_KNOCK_FRAME_LEN]) {
    if (!nonce_a || !token || !out) {
        return SHADOW_ERR_BAD_FRAME;
    }
    memcpy(out + 0, token, SHADOW_KNOCK_TOKEN_LEN);
    put_be64(out + 8, id_a);
    memcpy(out + 16, nonce_a, SHADOW_NONCE_LEN);
    out[32] = SHADOW_PROTOCOL_VERSION;
    out[33] = 0u;            /* flags */
    out[34] = 0u;            /* reserved */
    out[35] = 0u;            /* reserved */
    return SHADOW_OK;
}

/* DataHeader layout (32 bytes):
 *   version[1] | msg[1] | reserved[2] | seq[8] | id_a[8] | id_g[4] | utc_s[8]
 */
shadow_status_t shadow_protocol_pack_header(uint8_t msg, uint64_t seq,
                                            uint64_t id_a, uint32_t id_g,
                                            uint64_t utc_s,
                                            uint8_t out[SHADOW_DATA_HEADER_LEN]) {
    if (!out) return SHADOW_ERR_BAD_FRAME;
    out[0] = SHADOW_PROTOCOL_VERSION;
    out[1] = msg;
    out[2] = 0u;
    out[3] = 0u;
    put_be64(out + 4,  seq);
    put_be64(out + 12, id_a);
    put_be32(out + 20, id_g);
    put_be64(out + 24, utc_s);
    return SHADOW_OK;
}

shadow_status_t shadow_protocol_unpack_header(const uint8_t in[SHADOW_DATA_HEADER_LEN],
                                              uint8_t *msg, uint64_t *seq,
                                              uint64_t *id_a, uint32_t *id_g,
                                              uint64_t *utc_s) {
    if (!in) return SHADOW_ERR_BAD_FRAME;
    if (in[0] != SHADOW_PROTOCOL_VERSION) return SHADOW_ERR_BAD_FRAME;
    if (in[2] != 0u || in[3] != 0u)        return SHADOW_ERR_BAD_FRAME;
    if (msg)   *msg   = in[1];
    if (seq)   *seq   = get_be64(in + 4);
    if (id_a)  *id_a  = get_be64(in + 12);
    if (id_g)  *id_g  = get_be32(in + 20);
    if (utc_s) *utc_s = get_be64(in + 24);
    return SHADOW_OK;
}

/* IV derivation: iv_seq = iv_base XOR (00..00 || U64BE(seq)). */
void shadow_protocol_iv_for_seq(const uint8_t iv_base[SHADOW_AEAD_IV_LEN],
                                uint64_t seq,
                                uint8_t iv_out[SHADOW_AEAD_IV_LEN]) {
    uint8_t seq_be[8];
    put_be64(seq_be, seq);
    memcpy(iv_out, iv_base, SHADOW_AEAD_IV_LEN);
    for (size_t i = 0; i < 8; i++) {
        iv_out[4 + i] ^= seq_be[i];
    }
}

int shadow_ct_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= (uint8_t)(x[i] ^ y[i]);
    }
    return (int)acc;
}
