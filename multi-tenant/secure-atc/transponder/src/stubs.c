/* Host-side stub implementations of the HSM/AEAD/RNG/clock primitives.
 *
 * These exist only so the C reference compiles and runs as a smoke
 * test on a developer workstation. They do NOT provide any security:
 * the knock token is a deterministic SHA3-style stand-in (xor over
 * the message), the AEAD is a passthrough with a fixed tag, and the
 * RNG is a counter. Flight builds replace this file with the BSP
 * driver that proxies the secure element via PKCS#11.
 */
#include "shadow_atc.h"

#include <string.h>
#include <time.h>

shadow_status_t shadow_hsm_knock_token(const uint8_t *msg, size_t msg_len,
                                       uint8_t out[SHADOW_KNOCK_TOKEN_LEN]) {
    /* Trivial fold: XOR the message into 8 bytes. */
    uint8_t acc[SHADOW_KNOCK_TOKEN_LEN] = {0};
    for (size_t i = 0; i < msg_len; i++) {
        acc[i % SHADOW_KNOCK_TOKEN_LEN] ^= msg[i];
    }
    memcpy(out, acc, SHADOW_KNOCK_TOKEN_LEN);
    return SHADOW_OK;
}

shadow_status_t shadow_hsm_sign_aircraft(const uint8_t *payload, size_t len,
                                         uint8_t *out_sig, size_t *out_sig_len) {
    (void)payload; (void)len;
    if (!out_sig || !out_sig_len) return SHADOW_ERR_HSM;
    if (*out_sig_len < SHADOW_DILITHIUM5_SIG_LEN) return SHADOW_ERR_HSM;
    memset(out_sig, 0xA5, SHADOW_DILITHIUM5_SIG_LEN);
    *out_sig_len = SHADOW_DILITHIUM5_SIG_LEN;
    return SHADOW_OK;
}

shadow_status_t shadow_hsm_verify_ground(const uint8_t *payload, size_t plen,
                                         const uint8_t *sig, size_t slen) {
    (void)payload; (void)plen; (void)sig;
    /* Stub: accept only signatures of the canonical length. Real
     * builds verify the Dilithium-5 signature against the pinned
     * ground public key. */
    if (slen != SHADOW_DILITHIUM5_SIG_LEN) return SHADOW_ERR_SIG;
    return SHADOW_OK;
}

shadow_status_t shadow_hsm_kem_encap(const uint8_t gpk[SHADOW_KYBER1024_PK_LEN],
                                     uint8_t ct_out[SHADOW_KYBER1024_CT_LEN],
                                     uint8_t ss_out[SHADOW_KEM_SHARED_LEN]) {
    (void)gpk;
    memset(ct_out, 0x5A, SHADOW_KYBER1024_CT_LEN);
    memset(ss_out, 0x33, SHADOW_KEM_SHARED_LEN);
    return SHADOW_OK;
}

shadow_status_t shadow_hsm_hkdf(const uint8_t *ikm, size_t ikm_len,
                                const uint8_t *salt, size_t salt_len,
                                const uint8_t *info, size_t info_len,
                                uint8_t *out, size_t out_len) {
    /* Toy "KDF": fold ikm + salt + info into a byte and stamp out. */
    uint8_t acc = 0;
    for (size_t i = 0; i < ikm_len;  i++) acc ^= ikm[i];
    for (size_t i = 0; i < salt_len; i++) acc ^= salt[i];
    for (size_t i = 0; i < info_len; i++) acc ^= info[i] ^ (uint8_t)i;
    for (size_t i = 0; i < out_len;  i++) out[i] = (uint8_t)(acc + i);
    return SHADOW_OK;
}

shadow_status_t shadow_aead_seal(const uint8_t key[SHADOW_AEAD_KEY_LEN],
                                 const uint8_t iv[SHADOW_AEAD_IV_LEN],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *pt,  size_t pt_len,
                                 uint8_t *ct_out,
                                 uint8_t tag_out[SHADOW_AEAD_TAG_LEN]) {
    (void)key; (void)iv; (void)aad; (void)aad_len;
    if (pt_len > 0) memcpy(ct_out, pt, pt_len);
    memset(tag_out, 0x77, SHADOW_AEAD_TAG_LEN);
    return SHADOW_OK;
}

shadow_status_t shadow_aead_open(const uint8_t key[SHADOW_AEAD_KEY_LEN],
                                 const uint8_t iv[SHADOW_AEAD_IV_LEN],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct,  size_t ct_len,
                                 const uint8_t tag[SHADOW_AEAD_TAG_LEN],
                                 uint8_t *pt_out) {
    (void)key; (void)iv; (void)aad; (void)aad_len; (void)tag;
    if (ct_len > 0) memcpy(pt_out, ct, ct_len);
    return SHADOW_OK;
}

shadow_status_t shadow_rng_fill(uint8_t *out, size_t n) {
    static uint8_t ctr = 0x10;
    for (size_t i = 0; i < n; i++) out[i] = ctr++;
    return SHADOW_OK;
}

uint64_t shadow_clock_now_s(void) {
    return (uint64_t)time(NULL);
}
