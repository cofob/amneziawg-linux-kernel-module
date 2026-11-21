#ifndef _AWG_RELAY_H
#define _AWG_RELAY_H

#include <linux/types.h>
#include <crypto/chacha.h>

enum awg_relay_lengths {
	AWG_RELAY_KEY_SIZE = CHACHA_KEY_SIZE,
	AWG_RELAY_PATH_MAX = 64,
};

/* Path data that the peer puts into the handshake initiation trailer.
 * awg_relay_seal zero-pads path to path_size. A relay reads it as
 * ChaCha20(key, packet[:12]) ^ packet[-tail_size:].
 */
struct awg_relay {
	u8 key[AWG_RELAY_KEY_SIZE];
	u8 path[AWG_RELAY_PATH_MAX];
	u8 path_len;
	u8 path_size;
};

size_t awg_relay_tail_size(const struct awg_relay *relay);
void awg_relay_seal(const struct awg_relay *relay, u8 *packet, size_t len);

#endif
