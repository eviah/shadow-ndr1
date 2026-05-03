/* SHADOW-ATC aircraft transponder reference skeleton.
 *
 * This is the public interface a flight-grade build target links
 * against. The implementation lives in src/. The shape mirrors the
 * Rust ground-station reference (../ground-station/src/lib.rs) so the
 * two sides can be cross-checked with the same protocol spec
 * (../docs/01-crypto-protocol.md, "SHADOW-COMM v1").
 *
 * Hardware notes:
 *   - All long-term keys (k_master, sk_a) live in a tamper-respondent
 *     secure element behind a PKCS#11 boundary. The functions below
 *     never expose plaintext key material to caller-visible memory.
 *   - All RAM holding session keys MUST be in a region the bootloader
 *     guarantees is wiped on reset and on any tamper trip.
 *   - Build with -ffreestanding -fstack-protector-strong -fno-builtin
 *     -fno-common -Wformat=2 -Wstack-usage=1024 (see Makefile).
 */
#ifndef SHADOW_ATC_H_
#define SHADOW_ATC_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Wire constants (must match docs/01-crypto-protocol.md) ---- */

#define SHADOW_PROTOCOL_VERSION   0x01u

#define SHADOW_KNOCK_WINDOW_S     30u
#define SHADOW_REKEY_INTERVAL_S   30u
#define SHADOW_HANDSHAKE_SKEW_S    1
#define SHADOW_SESSION_SKEW_S      2
#define SHADOW_IDLE_TIMEOUT_S     90u

#define SHADOW_KNOCK_TOKEN_LEN     8u
#define SHADOW_NONCE_LEN          16u
#define SHADOW_KEM_SHARED_LEN     32u
#define SHADOW_AEAD_KEY_LEN       32u
#define SHADOW_AEAD_IV_LEN        12u
#define SHADOW_AEAD_TAG_LEN       16u

#define SHADOW_KYBER1024_PK_LEN  1568u
#define SHADOW_KYBER1024_CT_LEN  1568u
#define SHADOW_DILITHIUM5_SIG_LEN 4627u

#define SHADOW_KNOCK_FRAME_LEN     36u
#define SHADOW_DATA_HEADER_LEN     32u
#define SHADOW_MAX_PAYLOAD       1024u

/* Message-type byte (DataHeader.msg). */
#define SHADOW_MSG_KNOCK      0x10u
#define SHADOW_MSG_KEM_OFFER  0x20u
#define SHADOW_MSG_KEM_RESP   0x21u
#define SHADOW_MSG_DATA       0x40u
#define SHADOW_MSG_REKEY_OFF  0x30u
#define SHADOW_MSG_REKEY_RSP  0x31u
#define SHADOW_MSG_CLOSE      0x50u

/* ---------- Status codes ---------------------------------------------- */

typedef enum {
    SHADOW_OK              = 0,
    SHADOW_ERR_BAD_FRAME   = -1,
    SHADOW_ERR_STATE       = -2,
    SHADOW_ERR_KEM         = -3,
    SHADOW_ERR_AEAD        = -4,
    SHADOW_ERR_SIG         = -5,
    SHADOW_ERR_REPLAY      = -6,
    SHADOW_ERR_SKEW        = -7,
    SHADOW_ERR_HSM         = -8,
    SHADOW_ERR_LOCKED      = -9,
    SHADOW_ERR_NO_KEYS     = -10,
    SHADOW_ERR_TIMEOUT     = -11,
    SHADOW_ERR_BUFFER      = -12
} shadow_status_t;

/* ---------- Session state --------------------------------------------- */

typedef enum {
    SHADOW_STATE_QUIESCENT = 0,
    SHADOW_STATE_KNOCKED   = 1,
    SHADOW_STATE_AWAIT_OFFER = 2,
    SHADOW_STATE_ESTABLISHED = 3,
    SHADOW_STATE_REKEYING  = 4,
    SHADOW_STATE_CLOSED    = 5
} shadow_state_t;

/* Replay window: 256-bit bitmap, head = highest-seen seq. */
typedef struct {
    uint64_t head;
    uint64_t bits[4]; /* 256 bits */
} shadow_replay_t;

/* Session keys held in tamper-volatile RAM. Wipe with shadow_session_wipe(). */
typedef struct {
    uint8_t k_ag[SHADOW_AEAD_KEY_LEN]; /* aircraft -> ground */
    uint8_t k_ga[SHADOW_AEAD_KEY_LEN]; /* ground   -> aircraft */
    uint8_t iv_ag[SHADOW_AEAD_IV_LEN];
    uint8_t iv_ga[SHADOW_AEAD_IV_LEN];
} shadow_keys_t;

typedef struct {
    shadow_state_t state;
    uint64_t       id_a;
    uint32_t       id_g;
    uint64_t       tx_seq;
    shadow_replay_t rx_window;
    shadow_keys_t  keys;
    uint64_t       last_traffic_s;
    uint64_t       last_rekey_s;
    /* Pending handshake bookkeeping. */
    uint8_t        nonce_a[SHADOW_NONCE_LEN];
    uint8_t        nonce_g[SHADOW_NONCE_LEN];
    uint64_t       offer_sent_s;
} shadow_session_t;

/* ---------- HSM-backed primitives (driver-provided) ------------------- */
/*
 * These are NOT defined in the reference. The flight-software vendor
 * supplies a board-support implementation that proxies to the secure
 * element. See docs/02-hsm-config.md.
 *
 * Each function returns SHADOW_OK on success or SHADOW_ERR_HSM on any
 * fault. The implementations MUST be constant-time over secret data.
 */

/* HMAC-SHA3-256(K_master, msg)[:8]; out is 8 bytes. */
shadow_status_t shadow_hsm_knock_token(const uint8_t *msg, size_t msg_len,
                                       uint8_t out[SHADOW_KNOCK_TOKEN_LEN]);

/* Sign payload with the aircraft long-term Dilithium-5 key.
 * out_sig must be at least SHADOW_DILITHIUM5_SIG_LEN bytes. */
shadow_status_t shadow_hsm_sign_aircraft(const uint8_t *payload, size_t len,
                                         uint8_t *out_sig, size_t *out_sig_len);

/* Verify a Dilithium-5 signature claimed to be the ground long-term key.
 * The pinned ground public key is held inside the HSM. */
shadow_status_t shadow_hsm_verify_ground(const uint8_t *payload, size_t plen,
                                         const uint8_t *sig, size_t slen);

/* Encapsulate against a ground Kyber-1024 encapsulation key.
 * gpk: SHADOW_KYBER1024_PK_LEN bytes
 * ct_out: caller-supplied buffer of at least SHADOW_KYBER1024_CT_LEN bytes
 * ss_out: 32-byte shared secret (treat as secret; will be HKDF-derived). */
shadow_status_t shadow_hsm_kem_encap(const uint8_t gpk[SHADOW_KYBER1024_PK_LEN],
                                     uint8_t ct_out[SHADOW_KYBER1024_CT_LEN],
                                     uint8_t ss_out[SHADOW_KEM_SHARED_LEN]);

/* HKDF-SHA3-512 expansion. The implementation MUST run in tamper-volatile
 * RAM; the driver wipes intermediate state. */
shadow_status_t shadow_hsm_hkdf(const uint8_t *ikm, size_t ikm_len,
                                const uint8_t *salt, size_t salt_len,
                                const uint8_t *info, size_t info_len,
                                uint8_t *out, size_t out_len);

/* AES-256-GCM. Direction-specific keys come from shadow_keys_t. */
shadow_status_t shadow_aead_seal(const uint8_t key[SHADOW_AEAD_KEY_LEN],
                                 const uint8_t iv[SHADOW_AEAD_IV_LEN],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *pt,  size_t pt_len,
                                 uint8_t *ct_out,
                                 uint8_t tag_out[SHADOW_AEAD_TAG_LEN]);

shadow_status_t shadow_aead_open(const uint8_t key[SHADOW_AEAD_KEY_LEN],
                                 const uint8_t iv[SHADOW_AEAD_IV_LEN],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct,  size_t ct_len,
                                 const uint8_t tag[SHADOW_AEAD_TAG_LEN],
                                 uint8_t *pt_out);

/* Constant-time random bytes from the on-board TRNG. */
shadow_status_t shadow_rng_fill(uint8_t *out, size_t n);

/* TAI seconds-since-epoch, from the GNSS-disciplined clock. */
uint64_t        shadow_clock_now_s(void);

/* ---------- Session API ----------------------------------------------- */

/* Initialise a session in the QUIESCENT state. */
void shadow_session_init(shadow_session_t *s, uint64_t id_a, uint32_t id_g);

/* Wipe all secret material; safe to call from a tamper ISR. */
void shadow_session_wipe(shadow_session_t *s);

/* Compose an outbound KNOCK frame.
 *   buf must be at least SHADOW_KNOCK_FRAME_LEN bytes.
 *   *buf_len is set to SHADOW_KNOCK_FRAME_LEN on success.
 * Advances state from QUIESCENT to KNOCKED. */
shadow_status_t shadow_make_knock(shadow_session_t *s,
                                  uint64_t now_s,
                                  uint8_t *buf, size_t *buf_len);

/* Process an inbound KEM_OFFER and produce a KEM_RESP.
 *   in: pointer to the OFFER bytes
 *   in_len: length
 *   out_buf: where to write the RESP wire bytes
 *   out_buf_cap: capacity of out_buf (must be >= ~6.3 KiB)
 *   *out_len: actual bytes written
 * Advances state from KNOCKED to ESTABLISHED. */
shadow_status_t shadow_handle_offer(shadow_session_t *s,
                                    const uint8_t *in, size_t in_len,
                                    uint64_t now_s,
                                    uint8_t *out_buf, size_t out_buf_cap,
                                    size_t *out_len);

/* Encrypt application data (aircraft -> ground). */
shadow_status_t shadow_encrypt_app(shadow_session_t *s,
                                   const uint8_t *pt, size_t pt_len,
                                   uint64_t now_s,
                                   uint8_t *out_buf, size_t out_buf_cap,
                                   size_t *out_len);

/* Decrypt application data (ground -> aircraft) and check the replay window. */
shadow_status_t shadow_decrypt_app(shadow_session_t *s,
                                   const uint8_t *wire, size_t wire_len,
                                   uint64_t now_s,
                                   uint8_t *pt_out, size_t pt_cap,
                                   size_t *pt_len);

/* Periodic tick: tears down on idle and reports rekey-due state.
 * Returns 1 if a rekey is due, 0 otherwise. */
int shadow_session_tick(shadow_session_t *s, uint64_t now_s);

/* Constant-time memcmp returning 0 on equal, nonzero on different. */
int shadow_ct_memcmp(const void *a, const void *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* SHADOW_ATC_H_ */
