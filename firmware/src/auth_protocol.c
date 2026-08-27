#include <psa/crypto.h>
#include <zephyr/kernel.h>
#include <string.h>
#include "auth_protocol.h"
#include "programmer_pubkey.h"

#define PROGRAMMER_ID     "PROG0001"
#define PROGRAMMER_ID_LEN (sizeof(PROGRAMMER_ID) - 1)
#define NONCE_LEN 32
#define SIGNATURE_LEN 64  /* raw r || s for P-256, 32 bytes each */

void auth_protocol_init(void)
{
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printk("[AuthProtocol] psa_crypto_init failed: %d\n", status);
    } else {
        printk("[AuthProtocol] PSA Crypto initialized\n");
    }
}

bool auth_protocol_verify_response(const uint8_t *nonce, const uint8_t *signature, size_t sig_len)
{
    if (sig_len != SIGNATURE_LEN) {
        printk("[AuthProtocol] Signature length %u != expected %d\n",
               (unsigned)sig_len, SIGNATURE_LEN);
        return false;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, programmer_pubkey,
                                          sizeof(programmer_pubkey), &key_id);
    if (status != PSA_SUCCESS) {
        printk("[AuthProtocol] psa_import_key failed: %d\n", status);
        return false;
    }

    uint8_t message[NONCE_LEN + PROGRAMMER_ID_LEN];
    memcpy(message, nonce, NONCE_LEN);
    memcpy(message + NONCE_LEN, PROGRAMMER_ID, PROGRAMMER_ID_LEN);

    status = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                 message, sizeof(message),
                                 signature, sig_len);

    psa_destroy_key(key_id);

    if (status == PSA_SUCCESS) {
        printk("[AuthProtocol] ECDSA verification: PASS\n");
        return true;
    }
    printk("[AuthProtocol] ECDSA verification: FAIL (status %d)\n", status);
    return false;
}