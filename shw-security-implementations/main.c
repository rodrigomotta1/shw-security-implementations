#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <ctype.h>


#include "nrf.h"
#include "nrf_drv_clock.h"
#include "nrf_delay.h"

#include "nrf_drv_power.h"

#include "app_error.h"
#include "app_util.h"

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "boards.h"

#include "nrf_crypto.h"
#include "nrf_crypto_error.h"
#include "mem_manager.h"


#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "sdk_common.h"

#include "nrf_assert.h"

#include "app_error.h"
#include "app_util.h"

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_error.h"
#include "nrf_crypto_ecdsa.h"

#include "nrf.h"
#include "nrf_drv_clock.h"
#include "nrf_delay.h"
#include "nrf_drv_power.h"

#include "mem_manager.h"
#include "boards.h"

#include "data_protection.h"

#if !NRF_MODULE_ENABLED(NRF_CRYPTO)
#error This program requires NRF_CRYPTO. Enable it in sdk_config.h
#endif

#if !NRF_CRYPTO_ECC_SECP256R1_ENABLED
#error This program requires ECDSA SECP256R1. Enable it in sdk_config.h
#endif


int main(void)
{
    ret_code_t ret;

    APP_ERROR_CHECK(NRF_LOG_INIT(NULL));
    NRF_LOG_DEFAULT_BACKENDS_INIT();

    NRF_LOG_RAW_INFO("---- Inicio dos testes de implementacao dos controles de seguranca do Smart Health Wearable----\r\n");
    NRF_LOG_FLUSH();

    ret = nrf_drv_clock_init();
    APP_ERROR_CHECK(ret);
    nrf_drv_clock_lfclk_request(NULL);

    ret = nrf_crypto_init();
    APP_ERROR_CHECK(ret);

#if NRF_CRYPTO_BACKEND_MBEDTLS_ENABLED
    ret = nrf_mem_init();
    APP_ERROR_CHECK(ret);
#endif

    // Setup encrypted buffer
    char encrypted_buffer[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
    memset(encrypted_buffer,  0, sizeof(encrypted_buffer));
    size_t encrypted_data_size = sizeof(encrypted_buffer);

    // Setup decrypted buffer
    char decrypted_buffer[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
    memset(decrypted_buffer,  0, sizeof(decrypted_buffer));
    size_t decrypted_data_size = sizeof(decrypted_buffer);

    // Signature buffer
    nrf_crypto_ecdsa_secp256r1_signature_t m_signature;

    // Signature buffer size
    size_t m_signature_size = sizeof(m_signature);
    
    // AES CBC 128 bit key (only 128 bits are used from here due to CC310 lib limitation)
    uint8_t aes_key[32] = {
        'v', 'e', '3', 'e', 'i', 'X', 'o', 'h', '9',
        'a', 'e', '3', 'g', 'o', 'i', 'p', 'h', 'o',
        'e', 'z', 'a', 'e', 'T', 'h', 'a', 'e', 'k',
        'e', 'B', 'a', 'e', 'g'
    };
     
    // ECDSA secp256r1 private key bytes - extracted from openssl with help of a python script
    uint8_t raw_private_key[] =
    {
      0x77, 0xc5, 0x1b, 0x76, 0xce, 0xc0, 0xb5, 0xac, 
      0x76, 0xa2, 0x68, 0x9a, 0xe8, 0x0b, 0x3a, 0x36, 
      0xff, 0x2f, 0x5b, 0xdc, 0x5e, 0x8a, 0xda, 0x0f, 
      0x03, 0x74, 0x2d, 0x94, 0xcc, 0x36, 0x8a, 0xb5
    };
    
    // ECDSA secp256r1 public key bytes - extracted from openssl with help of a python script
    uint8_t raw_public_key[] =
    {
        0xda, 0xcb, 0xa2, 0xc5, 0xf9, 0x9d, 0x13, 0x87, 
        0x6d, 0x3d, 0xdb, 0x39, 0x96, 0x32, 0x8a, 0xc1, 
        0xda, 0x8f, 0xf2, 0x97, 0x6a, 0x5b, 0xc8, 0x52, 
        0xe1, 0x2b, 0xb4, 0x82, 0x87, 0x6c, 0xd6, 0x34, 
        0xce, 0x1a, 0x47, 0x3c, 0x4a, 0x77, 0xdf, 0xd7, 
        0x11, 0x31, 0xbb, 0x2e, 0xc2, 0x4f, 0x1e, 0x6d, 
        0xce, 0x2a, 0xeb, 0x9a, 0x60, 0x6e, 0x33, 0xb3, 
        0x84, 0x04, 0x62, 0x26, 0x17, 0x41, 0xa5, 0x69
    };
    

    // Establish data packet
    // Ideally, this packet will be defined as the wearable makes the necessary measures, abstracted by read_body functions
    DataPacket vitalSigns;
    const uint64_t wearable_uuid[] = {0xbf4ce634e1484540, 0x83dd7b0616f0709a};

    memcpy(vitalSigns.uuid, wearable_uuid, sizeof(uint64_t) * 2);

    vitalSigns.temperature  = read_body_temperature();
    vitalSigns.heartRate    = read_body_heartBeat();
    vitalSigns.spo2         = read_body_spo2();

    vitalSigns.msgType      = MTYPE_DATA;
    vitalSigns.button       = 0;

    size_t vitalSigns_size = sizeof(DataPacket);
    
    plain_text_print(&vitalSigns);

    // Encrypt packet
    aes_cbc_encrypt((uint8_t*) &vitalSigns, vitalSigns_size, encrypted_buffer, &encrypted_data_size, aes_key);
    encrypted_text_print(encrypted_buffer, encrypted_data_size);

    // Sign packet
    ecdsa_sign((uint8_t*) encrypted_buffer, encrypted_data_size,  m_signature, &m_signature_size, raw_private_key, sizeof(raw_private_key));
    hex_text_print("Assinatura", m_signature, m_signature_size);

    // Verify packet
    ecdsa_verify((uint8_t*) encrypted_buffer, encrypted_data_size, m_signature, m_signature_size, raw_public_key, sizeof(raw_public_key));

    // Decrypt packet
    aes_cbc_decrypt(encrypted_buffer, encrypted_data_size, decrypted_buffer, &decrypted_data_size, aes_key);
    decrypted_text_print(decrypted_buffer, decrypted_data_size);

    // Send packet

    while (true)
    {
        NRF_LOG_FLUSH();
        UNUSED_RETURN_VALUE(NRF_LOG_PROCESS());
    }

    // modificar nome do módulo para data_protection_utils

}


