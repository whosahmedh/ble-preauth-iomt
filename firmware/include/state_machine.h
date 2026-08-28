#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

#include <zephyr/bluetooth/conn.h>
#include <stdint.h>
#include <stdbool.h>

void state_machine_init(void);
void state_machine_on_connected(struct bt_conn *conn);
void state_machine_on_disconnected(struct bt_conn *conn);
const uint8_t *state_machine_get_nonce(void);
bool state_machine_on_response(struct bt_conn *conn, const uint8_t *signature, uint16_t len);
const uint8_t *state_machine_get_session_token(void);
bool state_machine_is_authenticated(struct bt_conn *conn);
void state_machine_on_bonded(struct bt_conn *conn);

#endif