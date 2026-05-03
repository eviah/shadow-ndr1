/* Knock-token derivation (spec §3).
 *
 * The aircraft never sees k_master[A] in the clear: shadow_hsm_knock_token()
 * runs HMAC-SHA3-256 inside the secure element and returns the truncated
 * 8-byte tag.
 */
#include "shadow_atc.h"
#include "protocol_internal.h"

#include <string.h>

/* Build the canonical knock-token message:
 *   "SHADOW-COMM/v1/knock" || U64BE(id_a) || U32BE(id_g) || U64BE(bucket)
 * Then ask the HSM to HMAC it with k_master[A] and truncate to 8 bytes.
 */
#define SHADOW_KNOCK_PREFIX     "SHADOW-COMM/v1/knock"
#define SHADOW_KNOCK_PREFIX_LEN 20u   /* strlen("SHADOW-COMM/v1/knock") */

shadow_status_t shadow_knock_token_msg(uint64_t id_a, uint32_t id_g,
                                       uint64_t bucket,
                                       uint8_t out[SHADOW_KNOCK_TOKEN_LEN]) {
    uint8_t msg[SHADOW_KNOCK_PREFIX_LEN + 8 + 4 + 8];
    memcpy(msg, SHADOW_KNOCK_PREFIX, SHADOW_KNOCK_PREFIX_LEN);
    uint8_t *p = msg + SHADOW_KNOCK_PREFIX_LEN;

    p[0] = (uint8_t)(id_a >> 56); p[1] = (uint8_t)(id_a >> 48);
    p[2] = (uint8_t)(id_a >> 40); p[3] = (uint8_t)(id_a >> 32);
    p[4] = (uint8_t)(id_a >> 24); p[5] = (uint8_t)(id_a >> 16);
    p[6] = (uint8_t)(id_a >> 8);  p[7] = (uint8_t)id_a;
    p += 8;

    p[0] = (uint8_t)(id_g >> 24); p[1] = (uint8_t)(id_g >> 16);
    p[2] = (uint8_t)(id_g >> 8);  p[3] = (uint8_t)id_g;
    p += 4;

    p[0] = (uint8_t)(bucket >> 56); p[1] = (uint8_t)(bucket >> 48);
    p[2] = (uint8_t)(bucket >> 40); p[3] = (uint8_t)(bucket >> 32);
    p[4] = (uint8_t)(bucket >> 24); p[5] = (uint8_t)(bucket >> 16);
    p[6] = (uint8_t)(bucket >> 8);  p[7] = (uint8_t)bucket;

    return shadow_hsm_knock_token(msg, sizeof(msg), out);
}
