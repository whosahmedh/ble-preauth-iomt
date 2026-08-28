#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/random/random.h>
#include <string.h>
#include "state_machine.h"
#include "auth_protocol.h"

#define NONCE_LEN 32
#define SESSION_TOKEN_LEN 32
#define SESSION_TOKEN_TIMEOUT_MS (30 * 1000)

typedef enum {
    STATE_IDLE,
    STATE_CONNECTED_UNAUTH,
    STATE_CHALLENGE_SENT,
    STATE_VERIFYING,
    STATE_AUTHENTICATED,
    STATE_BONDED_SESSION,
    STATE_DISCONNECTED
} auth_state_t;

static auth_state_t current_state;
static uint8_t current_nonce[NONCE_LEN];
static uint8_t current_session_token[SESSION_TOKEN_LEN];
static struct bt_conn *authenticated_conn;
static struct k_timer session_timer;

static void reset_state(void)
{
    current_state = STATE_IDLE;
    memset(current_nonce, 0, sizeof(current_nonce));
    memset(current_session_token, 0, sizeof(current_session_token));
    authenticated_conn = NULL;
    k_timer_stop(&session_timer);
    printk("[IoMT] State: IDLE\n");
}

static void session_timer_expired(struct k_timer *timer)
{
    printk("[IoMT] Session token expired -> State: DISCONNECTED\n");
    struct bt_conn *conn = authenticated_conn;
    current_state = STATE_DISCONNECTED;
    if (conn) {
        bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    }
    reset_state();
}

void state_machine_init(void)
{
    k_timer_init(&session_timer, session_timer_expired, NULL);
    reset_state();
}

void state_machine_on_connected(struct bt_conn *conn)
{
    if (current_state != STATE_IDLE) {
        printk("[IoMT] Unexpected connection while not IDLE -> rejecting\n");
        bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        return;
    }
    current_state = STATE_CONNECTED_UNAUTH;
    printk("[IoMT] Programmer connected -> State: CONNECTED_UNAUTH\n");

    sys_csrand_get(current_nonce, sizeof(current_nonce));
    current_state = STATE_CHALLENGE_SENT;
    printk("[IoMT] Nonce generated -> State: CHALLENGE_SENT\n");
}

void state_machine_on_disconnected(struct bt_conn *conn)
{
    printk("[IoMT] Disconnected\n");
    reset_state();
}

const uint8_t *state_machine_get_nonce(void)
{
    return current_nonce;
}

bool state_machine_on_response(struct bt_conn *conn, const uint8_t *signature, uint16_t len)
{
    if (current_state != STATE_CHALLENGE_SENT) {
        printk("[IoMT] Response received in wrong state -> rejecting\n");
        return false;
    }
    current_state = STATE_VERIFYING;
    printk("[IoMT] Response received -> State: VERIFYING\n");

    /* Placeholder verification -- real ECDSA check arrives in Phase 4.
       Any non-empty response is treated as PASS for now, purely so the
       state machine itself can be tested end-to-end before crypto exists. */
    bool verified = auth_protocol_verify_response(current_nonce, signature, len);

    if (!verified) {
        printk("[IoMT] Verification: FAIL -> State: DISCONNECTED\n");
        current_state = STATE_DISCONNECTED;
        bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        reset_state();
        return false;
    }

    sys_csrand_get(current_session_token, sizeof(current_session_token));
    authenticated_conn = conn;
    current_state = STATE_AUTHENTICATED;
    k_timer_start(&session_timer, K_MSEC(SESSION_TOKEN_TIMEOUT_MS), K_NO_WAIT);
    printk("[IoMT] Verification: PASS -> Session token issued, State: AUTHENTICATED\n");
    return true;
}

const uint8_t *state_machine_get_session_token(void)
{
    return current_session_token;
}

bool state_machine_is_authenticated(struct bt_conn *conn)
{
    return (current_state == STATE_AUTHENTICATED || current_state == STATE_BONDED_SESSION)
           && authenticated_conn == conn;
}

void state_machine_on_bonded(struct bt_conn *conn)
{
    if (current_state != STATE_AUTHENTICATED || authenticated_conn != conn) {
        printk("[IoMT] Bond formed on unexpected connection -- ignoring\n");
        return;
    }
    k_timer_stop(&session_timer);
    current_state = STATE_BONDED_SESSION;
    printk("[IoMT] Bond formed\n");
    printk("[IoMT] State: BONDED_SESSION -- Secure session active\n");
}