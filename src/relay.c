#include "relay.h"
#include "device.h"

#include <linux/minmax.h>
#include <linux/string.h>

size_t awg_relay_tail_size(const struct awg_relay *relay)
{
	if (!relay || !relay->path_len ||
	    !memchr_inv(relay->key, 0, AWG_RELAY_KEY_SIZE))
		return 0;
	return max_t(size_t, relay->path_len, relay->path_size);
}

void awg_relay_seal(const struct awg_relay *relay, u8 *packet, size_t len)
{
	size_t n = awg_relay_tail_size(relay);
	struct chacha_state state;
	u32 key[CHACHA_KEY_WORDS];
	u8 iv[CHACHA_IV_SIZE] = { 0 };
	u8 plain[AWG_RELAY_PATH_MAX] = { 0 };
	int i;

	if (!n)
		return;

	for (i = 0; i < CHACHA_KEY_WORDS; ++i)
		key[i] = get_unaligned_le32(relay->key + i * 4);
	memcpy(iv + 4, packet, 12);
	chacha_init(&state, key, iv);

	memcpy(plain, relay->path, relay->path_len);
	chacha20_crypt(&state, plain, plain, n);
	memcpy(packet + len - n, plain, n);

	memzero_explicit(&plain, sizeof(plain));
	memzero_explicit(&state, sizeof(state));
	memzero_explicit(key, sizeof(key));
}
