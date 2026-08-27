#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/att.h>
#include "auth_uuids.h"
#include "state_machine.h"

static ssize_t read_challenge(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                               void *buf, uint16_t len, uint16_t offset)
{
    return bt_gatt_attr_read(conn, attr, buf, len, offset,
                              state_machine_get_nonce(), 32);
}

static ssize_t write_response(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                               const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
    state_machine_on_response(conn, (const uint8_t *)buf, len);
    return len;
}

static ssize_t read_session_token(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                   void *buf, uint16_t len, uint16_t offset)
{
    if (!state_machine_is_authenticated(conn)) {
        return BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION);
    }
    return bt_gatt_attr_read(conn, attr, buf, len, offset,
                              state_machine_get_session_token(), 32);
}

static void auth_status_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
    printk("Auth Status notifications %s\n", value ? "enabled" : "disabled");
}

BT_GATT_SERVICE_DEFINE(preauth_svc,
    BT_GATT_PRIMARY_SERVICE(BT_UUID_PREAUTH_SERVICE),

    BT_GATT_CHARACTERISTIC(BT_UUID_CHALLENGE,
                            BT_GATT_CHRC_READ,
                            BT_GATT_PERM_READ,
                            read_challenge, NULL, NULL),

    BT_GATT_CHARACTERISTIC(BT_UUID_RESPONSE,
                            BT_GATT_CHRC_WRITE,
                            BT_GATT_PERM_WRITE,
                            NULL, write_response, NULL),

    BT_GATT_CHARACTERISTIC(BT_UUID_AUTH_STATUS,
                            BT_GATT_CHRC_NOTIFY,
                            0,
                            NULL, NULL, NULL),
    BT_GATT_CCC(auth_status_ccc_cfg_changed,
                BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

    BT_GATT_CHARACTERISTIC(BT_UUID_SESSION_TOKEN,
                            BT_GATT_CHRC_READ,
                            BT_GATT_PERM_READ,
                            read_session_token, NULL, NULL),
);