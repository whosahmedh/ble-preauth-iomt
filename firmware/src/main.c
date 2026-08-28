#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include "auth_uuids.h"
#include "state_machine.h"
#include "auth_protocol.h"
#include <zephyr/bluetooth/conn.h>

#define DEVICE_NAME     CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)

static const struct bt_data ad[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_PREAUTH_SERVICE_VAL),
    BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

static void connected(struct bt_conn *conn, uint8_t err)
{
    if (err) {
        printk("Connection failed (err %u)\n", err);
        return;
    }
    state_machine_on_connected(conn);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
    printk("Disconnected (reason %u)\n", reason);
    state_machine_on_disconnected(conn);
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
};

static void auth_cancel(struct bt_conn *conn)
{
    printk("[IoMT] Pairing cancelled\n");
}

static void auth_pairing_confirm(struct bt_conn *conn)
{
    if (state_machine_is_authenticated(conn)) {
        printk("[IoMT] Pairing confirmed -- connection is AUTHENTICATED\n");
        bt_conn_auth_pairing_confirm(conn);
    } else {
        printk("[IoMT] Pairing REJECTED -- connection not AUTHENTICATED\n");
        bt_conn_auth_cancel(conn);
    }
}

static struct bt_conn_auth_cb conn_auth_callbacks = {
    .pairing_confirm = auth_pairing_confirm,
    .cancel = auth_cancel,
};

static void auth_pairing_complete(struct bt_conn *conn, bool bonded)
{
    printk("[IoMT] Pairing complete -- bonded: %s\n", bonded ? "yes" : "no");
    state_machine_on_bonded(conn);
}

static void auth_pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
    printk("[IoMT] Pairing failed (reason %d)\n", reason);
}

static struct bt_conn_auth_info_cb conn_auth_info_callbacks = {
    .pairing_complete = auth_pairing_complete,
    .pairing_failed = auth_pairing_failed,
};

static void bt_ready(int err)
{
    if (err) {
        printk("Bluetooth init failed (err %d)\n", err);
        return;
    }
    printk("Bluetooth initialized\n");

    err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), NULL, 0);
    if (err) {
        printk("Advertising failed to start (err %d)\n", err);
        return;
    }
    printk("Advertising started -- pre-auth GATT service discoverable\n");
}

#define RUN_CRYPTO_SELFTEST 0

#if RUN_CRYPTO_SELFTEST
static void run_crypto_test_vectors(void)
{
    uint8_t test_nonce[32];
    for (int i = 0; i < 32; i++) {
        test_nonce[i] = i;
    }

    /* PASTE the 64-value C array printed by sign_test.py here */
        uint8_t valid_signature[64] = {
        0x79, 0x9c, 0xd4, 0x27, 0x33, 0x0e, 0x2d, 0x40, 0x6c, 0xdb, 0xe1, 0x89, 0xa8, 0xf7, 0x20, 0x8f,
        0x01, 0xe1, 0x11, 0x54, 0xf1, 0xf3, 0xb8, 0xcd, 0x77, 0x48, 0xd3, 0xb6, 0xd8, 0x80, 0x66, 0x06,
        0x76, 0x49, 0xd4, 0x8f, 0x96, 0x8d, 0x40, 0x67, 0x0b, 0xe4, 0x45, 0x58, 0xd3, 0xe7, 0x7c, 0xf9,
        0x12, 0x72, 0x18, 0x23, 0xb7, 0xf2, 0x15, 0xc6, 0x21, 0x03, 0x5d, 0x5d, 0x93, 0x39, 0x7c, 0x01
    };

    int64_t start = k_uptime_get();
    bool result1 = auth_protocol_verify_response(test_nonce, valid_signature, sizeof(valid_signature));
    int64_t elapsed = k_uptime_get() - start;
    printk("[TEST] Valid signature -> verify returned: %s (expect PASS)\n",
           result1 ? "PASS" : "FAIL");
    printk("[TEST] Verify took %lld ms\n", elapsed);

    uint8_t corrupted_signature[64];
    memcpy(corrupted_signature, valid_signature, sizeof(valid_signature));
    corrupted_signature[0] ^= 0xFF;  /* deliberately corrupt one byte */

    bool result2 = auth_protocol_verify_response(test_nonce, corrupted_signature, sizeof(corrupted_signature));
    printk("[TEST] Corrupted signature -> verify returned: %s (expect FAIL)\n",
           result2 ? "PASS" : "FAIL");
}
#endif

int main(void)
{
    state_machine_init();
    bt_conn_auth_cb_register(&conn_auth_callbacks);
    bt_conn_auth_info_cb_register(&conn_auth_info_callbacks);
    
    auth_protocol_init();
    #if RUN_CRYPTO_SELFTEST
        run_crypto_test_vectors();
    #endif

    int err = bt_enable(bt_ready);
    if (err) {
        printk("bt_enable failed (err %d)\n", err);
    }
    return 0;
}