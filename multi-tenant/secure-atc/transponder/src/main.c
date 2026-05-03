/* Aircraft transponder reference entry point.
 *
 * On flight hardware this is the firmware main(). On a POSIX host
 * it is a smoke-test harness that wires up stub HSM/AEAD/RNG/clock
 * symbols (in stubs.c) so the protocol logic can be exercised
 * without a secure element.
 *
 * The flow models one full session:
 *   QUIESCENT --knock--> KNOCKED --offer--> ESTABLISHED --data-->
 */
#include "shadow_atc.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    shadow_session_t sess;
    shadow_session_init(&sess, 0xCAFEBABEull, 0xABCDu);

    uint64_t now = shadow_clock_now_s();

    /* Phase 1: KNOCK. */
    uint8_t knock_buf[SHADOW_KNOCK_FRAME_LEN];
    size_t knock_len = sizeof(knock_buf);
    shadow_status_t st = shadow_make_knock(&sess, now, knock_buf, &knock_len);
    if (st != SHADOW_OK) {
        fprintf(stderr, "knock failed: %d\n", st);
        return 1;
    }
    printf("KNOCK %zu bytes, state=%d\n", knock_len, sess.state);

    /* On real flight hardware we'd transmit knock_buf and receive an
     * OFFER; the stub harness has no peer, so we stop here. The shape
     * is validated: knock pack succeeds, state advanced. */
    shadow_session_wipe(&sess);
    return 0;
}
