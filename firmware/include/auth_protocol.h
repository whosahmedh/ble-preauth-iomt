#ifndef AUTH_PROTOCOL_H
#define AUTH_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void auth_protocol_init(void);
bool auth_protocol_verify_response(const uint8_t *nonce, const uint8_t *signature, size_t sig_len);

#endif