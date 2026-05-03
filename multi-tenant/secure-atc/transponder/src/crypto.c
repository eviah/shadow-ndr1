/* Replay window + KDF helpers. AEAD itself is provided by the HSM
 * driver; we only manage the seq-vs-window state here.
 */
#include "shadow_atc.h"
#include "protocol_internal.h"

#include <string.h>

/* 256-bit replay window: head = highest seq accepted; bits[0]'s LSB
 * represents (head - 0); bit i represents (head - i). On a frame whose
 * seq exceeds head, we left-shift the bitmap by the gap. */

#define WINDOW_BITS 256

static int test_bit(const shadow_replay_t *w, uint64_t off) {
    uint64_t word = off >> 6;
    uint64_t bit  = off & 63u;
    return (int)((w->bits[word] >> bit) & 1u);
}

static void set_bit(shadow_replay_t *w, uint64_t off) {
    uint64_t word = off >> 6;
    uint64_t bit  = off & 63u;
    w->bits[word] |= ((uint64_t)1u << bit);
}

static void shift_left(shadow_replay_t *w, uint64_t n) {
    if (n >= WINDOW_BITS) {
        memset(w->bits, 0, sizeof(w->bits));
        return;
    }
    uint64_t whole = n >> 6;
    uint64_t part  = n & 63u;
    if (whole > 0) {
        for (int64_t i = 3; i >= (int64_t)whole; i--) {
            w->bits[i] = w->bits[i - whole];
        }
        for (uint64_t i = 0; i < whole; i++) {
            w->bits[i] = 0u;
        }
    }
    if (part > 0) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t next = (w->bits[i] >> (64u - part));
            w->bits[i] = (w->bits[i] << part) | carry;
            carry = next;
        }
    }
}

/* Returns SHADOW_OK if seq is fresh and the window has been updated.
 * Returns SHADOW_ERR_REPLAY if seq is a replay or too far below head. */
shadow_status_t shadow_replay_check_and_set(shadow_replay_t *w, uint64_t seq) {
    if (w->head == 0u && w->bits[0] == 0u && w->bits[1] == 0u &&
        w->bits[2] == 0u && w->bits[3] == 0u) {
        /* First-frame fast path. */
        w->head = seq;
        set_bit(w, 0);
        return SHADOW_OK;
    }

    if (seq > w->head) {
        uint64_t gap = seq - w->head;
        shift_left(w, gap);
        w->head = seq;
        set_bit(w, 0);
        return SHADOW_OK;
    }

    uint64_t off = w->head - seq;
    if (off >= WINDOW_BITS) {
        return SHADOW_ERR_REPLAY;
    }
    if (test_bit(w, off)) {
        return SHADOW_ERR_REPLAY;
    }
    set_bit(w, off);
    return SHADOW_OK;
}
