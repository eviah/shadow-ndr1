/* Internal helpers shared between the transponder C source files.
 * Not part of the public API; do not export.
 */
#ifndef SHADOW_ATC_PROTOCOL_INTERNAL_H_
#define SHADOW_ATC_PROTOCOL_INTERNAL_H_

#include "shadow_atc.h"

#ifdef __cplusplus
extern "C" {
#endif

shadow_status_t shadow_protocol_pack_knock(uint64_t id_a,
                                           const uint8_t nonce_a[SHADOW_NONCE_LEN],
                                           const uint8_t token[SHADOW_KNOCK_TOKEN_LEN],
                                           uint8_t out[SHADOW_KNOCK_FRAME_LEN]);

shadow_status_t shadow_protocol_pack_header(uint8_t msg, uint64_t seq,
                                            uint64_t id_a, uint32_t id_g,
                                            uint64_t utc_s,
                                            uint8_t out[SHADOW_DATA_HEADER_LEN]);

shadow_status_t shadow_protocol_unpack_header(const uint8_t in[SHADOW_DATA_HEADER_LEN],
                                              uint8_t *msg, uint64_t *seq,
                                              uint64_t *id_a, uint32_t *id_g,
                                              uint64_t *utc_s);

void shadow_protocol_iv_for_seq(const uint8_t iv_base[SHADOW_AEAD_IV_LEN],
                                uint64_t seq,
                                uint8_t iv_out[SHADOW_AEAD_IV_LEN]);

/* knock.c */
shadow_status_t shadow_knock_token_msg(uint64_t id_a, uint32_t id_g,
                                       uint64_t bucket,
                                       uint8_t out[SHADOW_KNOCK_TOKEN_LEN]);

/* crypto.c */
shadow_status_t shadow_replay_check_and_set(shadow_replay_t *w, uint64_t seq);

/* HKDF info strings (must match Rust reference). Defined as macros so
 * sizeof() works at the call site and there is no extra symbol table
 * entry to verify in the flight-image audit. */
#define SHADOW_HKDF_INFO_KAG  "shadow-comm/v1/k_a_to_g"
#define SHADOW_HKDF_INFO_KGA  "shadow-comm/v1/k_g_to_a"
#define SHADOW_HKDF_INFO_IVAG "shadow-comm/v1/iv_a_to_g"
#define SHADOW_HKDF_INFO_IVGA "shadow-comm/v1/iv_g_to_a"

#ifdef __cplusplus
}
#endif

#endif /* SHADOW_ATC_PROTOCOL_INTERNAL_H_ */
