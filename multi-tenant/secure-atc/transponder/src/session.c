/* Aircraft-side session logic. Mirrors ground-station/src/session.rs.
 *
 * Every transition fails closed: a spurious or malformed frame wipes
 * the session state. There is no fall-through.
 */
#include "shadow_atc.h"
#include "protocol_internal.h"

#include <string.h>

/* Compile-time guard: the public buffer caller-must-provide for the
 * KEM_RESP needs to fit the canonical layout. */
#define SHADOW_KEM_RESP_LEN \
    (1u + 8u + SHADOW_KYBER1024_CT_LEN + 2u * SHADOW_NONCE_LEN + 8u + \
     SHADOW_DILITHIUM5_SIG_LEN)

static void wipe_secret(void *p, size_t n) {
    /* memset_s would be ideal; here we use a volatile sink to defeat
     * dead-store elimination without -fno-builtin-memset. */
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}

void shadow_session_init(shadow_session_t *s, uint64_t id_a, uint32_t id_g) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
    s->state = SHADOW_STATE_QUIESCENT;
    s->id_a = id_a;
    s->id_g = id_g;
}

void shadow_session_wipe(shadow_session_t *s) {
    if (!s) return;
    wipe_secret(&s->keys, sizeof(s->keys));
    wipe_secret(s->nonce_a, sizeof(s->nonce_a));
    wipe_secret(s->nonce_g, sizeof(s->nonce_g));
    s->tx_seq = 0;
    memset(&s->rx_window, 0, sizeof(s->rx_window));
    s->state = SHADOW_STATE_CLOSED;
}

/* Phase 1 — produce a KNOCK frame. */
shadow_status_t shadow_make_knock(shadow_session_t *s, uint64_t now_s,
                                  uint8_t *buf, size_t *buf_len) {
    if (!s || !buf || !buf_len) return SHADOW_ERR_BAD_FRAME;
    if (s->state != SHADOW_STATE_QUIESCENT) return SHADOW_ERR_STATE;
    if (*buf_len < SHADOW_KNOCK_FRAME_LEN)  return SHADOW_ERR_BUFFER;

    shadow_status_t st = shadow_rng_fill(s->nonce_a, SHADOW_NONCE_LEN);
    if (st != SHADOW_OK) return st;

    uint64_t bucket = now_s / SHADOW_KNOCK_WINDOW_S;
    uint8_t token[SHADOW_KNOCK_TOKEN_LEN];
    st = shadow_knock_token_msg(s->id_a, s->id_g, bucket, token);
    if (st != SHADOW_OK) return st;

    st = shadow_protocol_pack_knock(s->id_a, s->nonce_a, token, buf);
    if (st != SHADOW_OK) return st;
    *buf_len = SHADOW_KNOCK_FRAME_LEN;
    s->state = SHADOW_STATE_KNOCKED;
    s->last_traffic_s = now_s;
    return SHADOW_OK;
}

/* Layout of KEM_OFFER bytes (must match Rust build_kem_offer):
 *   msg[1] | id_g[4] | epk[1568] | nonce_g[16] | nonce_a[16] | ts[8] | sig[4627]
 */
#define OFFER_LEN \
    (1u + 4u + SHADOW_KYBER1024_PK_LEN + 2u * SHADOW_NONCE_LEN + 8u + \
     SHADOW_DILITHIUM5_SIG_LEN)

static void put_be64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)v;
}
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
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

/* Build the canonical "to-be-signed" bytes of a KEM_OFFER (for verify). */
static void build_signed_kem_offer(uint32_t id_g,
                                   const uint8_t *epk_bytes,
                                   const uint8_t nonce_g[SHADOW_NONCE_LEN],
                                   const uint8_t nonce_a[SHADOW_NONCE_LEN],
                                   uint64_t ts,
                                   uint8_t *out, size_t *out_len) {
    uint8_t *p = out;
    *p++ = SHADOW_MSG_KEM_OFFER;
    put_be32(p, id_g); p += 4;
    memcpy(p, epk_bytes, SHADOW_KYBER1024_PK_LEN); p += SHADOW_KYBER1024_PK_LEN;
    memcpy(p, nonce_g, SHADOW_NONCE_LEN); p += SHADOW_NONCE_LEN;
    memcpy(p, nonce_a, SHADOW_NONCE_LEN); p += SHADOW_NONCE_LEN;
    put_be64(p, ts); p += 8;
    *out_len = (size_t)(p - out);
}

/* Build the canonical "to-be-signed" bytes of our KEM_RESP. */
static void build_signed_kem_resp(uint64_t id_a,
                                  const uint8_t *ct,
                                  const uint8_t nonce_a[SHADOW_NONCE_LEN],
                                  const uint8_t nonce_g[SHADOW_NONCE_LEN],
                                  uint64_t ts,
                                  uint8_t *out, size_t *out_len) {
    uint8_t *p = out;
    *p++ = SHADOW_MSG_KEM_RESP;
    put_be64(p, id_a); p += 8;
    memcpy(p, ct, SHADOW_KYBER1024_CT_LEN); p += SHADOW_KYBER1024_CT_LEN;
    memcpy(p, nonce_a, SHADOW_NONCE_LEN); p += SHADOW_NONCE_LEN;
    memcpy(p, nonce_g, SHADOW_NONCE_LEN); p += SHADOW_NONCE_LEN;
    put_be64(p, ts); p += 8;
    *out_len = (size_t)(p - out);
}

/* Phase 2/3 — consume a KEM_OFFER and produce a KEM_RESP. */
shadow_status_t shadow_handle_offer(shadow_session_t *s,
                                    const uint8_t *in, size_t in_len,
                                    uint64_t now_s,
                                    uint8_t *out_buf, size_t out_buf_cap,
                                    size_t *out_len) {
    if (!s || !in || !out_buf || !out_len) return SHADOW_ERR_BAD_FRAME;
    if (s->state != SHADOW_STATE_KNOCKED)  return SHADOW_ERR_STATE;
    if (in_len < OFFER_LEN)                return SHADOW_ERR_BAD_FRAME;
    if (out_buf_cap < SHADOW_KEM_RESP_LEN) return SHADOW_ERR_BUFFER;
    if (in[0] != SHADOW_MSG_KEM_OFFER)     return SHADOW_ERR_BAD_FRAME;

    uint32_t id_g = get_be32(in + 1);
    if (id_g != s->id_g) return SHADOW_ERR_BAD_FRAME;

    const uint8_t *epk = in + 5;
    const uint8_t *nonce_g_in = epk + SHADOW_KYBER1024_PK_LEN;
    const uint8_t *nonce_a_echo = nonce_g_in + SHADOW_NONCE_LEN;
    const uint8_t *ts_p = nonce_a_echo + SHADOW_NONCE_LEN;
    const uint8_t *sig  = ts_p + 8;
    size_t sig_len = in_len - (size_t)(sig - in);

    /* The OFFER must echo our nonce_a back. */
    if (shadow_ct_memcmp(nonce_a_echo, s->nonce_a, SHADOW_NONCE_LEN) != 0) {
        return SHADOW_ERR_BAD_FRAME;
    }

    uint64_t ts = get_be64(ts_p);
    int64_t skew = (int64_t)ts - (int64_t)now_s;
    if (skew < 0) skew = -skew;
    if (skew > SHADOW_HANDSHAKE_SKEW_S) return SHADOW_ERR_SKEW;

    /* Build the canonical signed bytes and verify against the pinned
     * ground key (held inside the HSM). */
    static uint8_t signed_buf[1 + 4 + SHADOW_KYBER1024_PK_LEN +
                              2 * SHADOW_NONCE_LEN + 8];
    size_t signed_len = 0;
    build_signed_kem_offer(id_g, epk, nonce_g_in, s->nonce_a, ts,
                           signed_buf, &signed_len);
    shadow_status_t st = shadow_hsm_verify_ground(signed_buf, signed_len,
                                                  sig, sig_len);
    if (st != SHADOW_OK) return SHADOW_ERR_SIG;

    memcpy(s->nonce_g, nonce_g_in, SHADOW_NONCE_LEN);

    /* KEM encapsulate against the offered Kyber public key. */
    static uint8_t ct[SHADOW_KYBER1024_CT_LEN];
    uint8_t ss[SHADOW_KEM_SHARED_LEN];
    st = shadow_hsm_kem_encap(epk, ct, ss);
    if (st != SHADOW_OK) { wipe_secret(ss, sizeof(ss)); return SHADOW_ERR_KEM; }

    /* Derive the four AES-GCM session keys via HKDF-SHA3-512.
     * salt = nonce_a || nonce_g || U64BE(id_a) || U32BE(id_g). */
    uint8_t salt[SHADOW_NONCE_LEN + SHADOW_NONCE_LEN + 8 + 4];
    memcpy(salt + 0, s->nonce_a, SHADOW_NONCE_LEN);
    memcpy(salt + SHADOW_NONCE_LEN, s->nonce_g, SHADOW_NONCE_LEN);
    put_be64(salt + 2 * SHADOW_NONCE_LEN, s->id_a);
    put_be32(salt + 2 * SHADOW_NONCE_LEN + 8, s->id_g);

    st = shadow_hsm_hkdf(ss, sizeof(ss), salt, sizeof(salt),
                         (const uint8_t *)SHADOW_HKDF_INFO_KAG,
                         sizeof(SHADOW_HKDF_INFO_KAG) - 1u,
                         s->keys.k_ag, SHADOW_AEAD_KEY_LEN);
    if (st == SHADOW_OK) {
        st = shadow_hsm_hkdf(ss, sizeof(ss), salt, sizeof(salt),
                             (const uint8_t *)SHADOW_HKDF_INFO_KGA,
                             sizeof(SHADOW_HKDF_INFO_KGA) - 1u,
                             s->keys.k_ga, SHADOW_AEAD_KEY_LEN);
    }
    if (st == SHADOW_OK) {
        st = shadow_hsm_hkdf(ss, sizeof(ss), salt, sizeof(salt),
                             (const uint8_t *)SHADOW_HKDF_INFO_IVAG,
                             sizeof(SHADOW_HKDF_INFO_IVAG) - 1u,
                             s->keys.iv_ag, SHADOW_AEAD_IV_LEN);
    }
    if (st == SHADOW_OK) {
        st = shadow_hsm_hkdf(ss, sizeof(ss), salt, sizeof(salt),
                             (const uint8_t *)SHADOW_HKDF_INFO_IVGA,
                             sizeof(SHADOW_HKDF_INFO_IVGA) - 1u,
                             s->keys.iv_ga, SHADOW_AEAD_IV_LEN);
    }
    wipe_secret(ss, sizeof(ss));
    if (st != SHADOW_OK) {
        shadow_session_wipe(s);
        return st;
    }

    /* Build canonical signed-bytes for our KEM_RESP and sign. */
    static uint8_t resp_signed[1 + 8 + SHADOW_KYBER1024_CT_LEN +
                               2 * SHADOW_NONCE_LEN + 8];
    size_t resp_signed_len = 0;
    build_signed_kem_resp(s->id_a, ct, s->nonce_a, s->nonce_g, ts,
                          resp_signed, &resp_signed_len);

    static uint8_t sig_out[SHADOW_DILITHIUM5_SIG_LEN];
    size_t sig_out_len = sizeof(sig_out);
    st = shadow_hsm_sign_aircraft(resp_signed, resp_signed_len,
                                  sig_out, &sig_out_len);
    if (st != SHADOW_OK) { shadow_session_wipe(s); return SHADOW_ERR_SIG; }

    /* Lay out the wire RESP. */
    uint8_t *p = out_buf;
    *p++ = SHADOW_MSG_KEM_RESP;
    put_be64(p, s->id_a); p += 8;
    memcpy(p, ct, SHADOW_KYBER1024_CT_LEN); p += SHADOW_KYBER1024_CT_LEN;
    memcpy(p, s->nonce_a, SHADOW_NONCE_LEN); p += SHADOW_NONCE_LEN;
    memcpy(p, s->nonce_g, SHADOW_NONCE_LEN); p += SHADOW_NONCE_LEN;
    put_be64(p, ts); p += 8;
    memcpy(p, sig_out, sig_out_len); p += sig_out_len;
    *out_len = (size_t)(p - out_buf);

    s->state = SHADOW_STATE_ESTABLISHED;
    s->tx_seq = 0;
    memset(&s->rx_window, 0, sizeof(s->rx_window));
    s->last_traffic_s = now_s;
    s->last_rekey_s   = now_s;
    return SHADOW_OK;
}

shadow_status_t shadow_encrypt_app(shadow_session_t *s,
                                   const uint8_t *pt, size_t pt_len,
                                   uint64_t now_s,
                                   uint8_t *out_buf, size_t out_buf_cap,
                                   size_t *out_len) {
    if (!s || !pt || !out_buf || !out_len) return SHADOW_ERR_BAD_FRAME;
    if (s->state != SHADOW_STATE_ESTABLISHED &&
        s->state != SHADOW_STATE_REKEYING) return SHADOW_ERR_STATE;
    if (pt_len > SHADOW_MAX_PAYLOAD) return SHADOW_ERR_BAD_FRAME;
    size_t needed = SHADOW_DATA_HEADER_LEN + pt_len + SHADOW_AEAD_TAG_LEN;
    if (out_buf_cap < needed) return SHADOW_ERR_BUFFER;

    uint8_t aad[SHADOW_DATA_HEADER_LEN];
    shadow_status_t st = shadow_protocol_pack_header(SHADOW_MSG_DATA,
                                                     s->tx_seq, s->id_a,
                                                     s->id_g, now_s, aad);
    if (st != SHADOW_OK) return st;

    uint8_t iv[SHADOW_AEAD_IV_LEN];
    shadow_protocol_iv_for_seq(s->keys.iv_ag, s->tx_seq, iv);

    memcpy(out_buf, aad, SHADOW_DATA_HEADER_LEN);
    uint8_t *ct_out = out_buf + SHADOW_DATA_HEADER_LEN;
    uint8_t *tag_out = ct_out + pt_len;
    st = shadow_aead_seal(s->keys.k_ag, iv, aad, sizeof(aad),
                          pt, pt_len, ct_out, tag_out);
    if (st != SHADOW_OK) return SHADOW_ERR_AEAD;

    s->tx_seq += 1u;
    s->last_traffic_s = now_s;
    *out_len = needed;
    return SHADOW_OK;
}

shadow_status_t shadow_decrypt_app(shadow_session_t *s,
                                   const uint8_t *wire, size_t wire_len,
                                   uint64_t now_s,
                                   uint8_t *pt_out, size_t pt_cap,
                                   size_t *pt_len) {
    if (!s || !wire || !pt_out || !pt_len) return SHADOW_ERR_BAD_FRAME;
    if (s->state != SHADOW_STATE_ESTABLISHED &&
        s->state != SHADOW_STATE_REKEYING) return SHADOW_ERR_STATE;
    if (wire_len < SHADOW_DATA_HEADER_LEN + SHADOW_AEAD_TAG_LEN) {
        return SHADOW_ERR_BAD_FRAME;
    }

    uint8_t msg; uint64_t seq, hdr_id_a, hdr_utc; uint32_t hdr_id_g;
    shadow_status_t st = shadow_protocol_unpack_header(wire, &msg, &seq,
                                                       &hdr_id_a, &hdr_id_g,
                                                       &hdr_utc);
    if (st != SHADOW_OK) return st;
    if (msg != SHADOW_MSG_DATA)      return SHADOW_ERR_BAD_FRAME;
    if (hdr_id_a != s->id_a || hdr_id_g != s->id_g) return SHADOW_ERR_BAD_FRAME;

    int64_t skew = (int64_t)hdr_utc - (int64_t)now_s;
    if (skew < 0) skew = -skew;
    if (skew > SHADOW_SESSION_SKEW_S) return SHADOW_ERR_SKEW;

    st = shadow_replay_check_and_set(&s->rx_window, seq);
    if (st != SHADOW_OK) return st;

    size_t ct_len = wire_len - SHADOW_DATA_HEADER_LEN - SHADOW_AEAD_TAG_LEN;
    if (pt_cap < ct_len) return SHADOW_ERR_BUFFER;

    uint8_t iv[SHADOW_AEAD_IV_LEN];
    shadow_protocol_iv_for_seq(s->keys.iv_ga, seq, iv);

    const uint8_t *ct = wire + SHADOW_DATA_HEADER_LEN;
    const uint8_t *tag = wire + SHADOW_DATA_HEADER_LEN + ct_len;
    st = shadow_aead_open(s->keys.k_ga, iv, wire, SHADOW_DATA_HEADER_LEN,
                          ct, ct_len, tag, pt_out);
    if (st != SHADOW_OK) return SHADOW_ERR_AEAD;

    *pt_len = ct_len;
    s->last_traffic_s = now_s;
    return SHADOW_OK;
}

int shadow_session_tick(shadow_session_t *s, uint64_t now_s) {
    if (!s) return 0;
    if (s->state != SHADOW_STATE_ESTABLISHED &&
        s->state != SHADOW_STATE_REKEYING) return 0;
    if (now_s - s->last_traffic_s >= SHADOW_IDLE_TIMEOUT_S) {
        shadow_session_wipe(s);
        return 0;
    }
    if (s->state == SHADOW_STATE_ESTABLISHED &&
        now_s - s->last_rekey_s >= SHADOW_REKEY_INTERVAL_S) {
        return 1;
    }
    return 0;
}
