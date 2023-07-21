#include <stdint.h>
#include <stddef.h>
#include "data_protection.h"

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_error.h"
#include "nrf_crypto_ecdsa.h"

void struct_print(char const* p_label, DataPacket* p_struct)
{
    NRF_LOG_RAW_INFO("---- %s (tamanho: %u) ----\r\n", p_label, sizeof(DataPacket));
    NRF_LOG_FLUSH();
    NRF_LOG_RAW_INFO("Temp: %.1f\nFreq: %d\nSPO2: %d\n", p_struct->temperature, p_struct->heartRate, p_struct->spo2);
    //printf("(printf) Temp: %.1f\nFreq: %d\nSPO2: %d\n", p_struct->temperature, p_struct->heartRate, p_struct->spo2);
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- fim %s ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}


void text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("----%s (tamanho: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();
    for(size_t i = 0; i < len; i++)
    {
        NRF_LOG_RAW_INFO("%c", p_text[i]);
        NRF_LOG_FLUSH();
    }
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- fim %s ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}


void hex_text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("---- %s (tamanho: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();

    // Handle partial line (left)
    for (size_t i = 0; i < len; i++)
    {
        if (((i & 0xF) == 0) && (i > 0))
        {
            NRF_LOG_RAW_INFO("\r\n");
            NRF_LOG_FLUSH();
        }

        NRF_LOG_RAW_INFO("%02x ", p_text[i]);
        NRF_LOG_FLUSH();
    }
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- fim %s ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}


void plain_text_print(DataPacket* ptr_packet)
{
    //text_print("Plain text", (char*)ptr_example_packet, strlen((char*)ptr_example_packet));
    struct_print("Conteudo do pacote", ptr_packet);
    hex_text_print("Conteudo do pacote (repr. hexadecimal)", (uint8_t *) ptr_packet, (size_t)sizeof(DataPacket));
}


void encrypted_text_print(char const * p_text, size_t encrypted_len)
{
    hex_text_print("Conteudo cifrado (repr. hexadecimal)", p_text, encrypted_len);
}

void decrypted_text_print(char const * p_text, size_t decrypted_len)
{
    struct_print("Conteudo do pacote", (struct data_packet*)p_text);
    hex_text_print("Conteudo decifrado (repr. hexadecimal)", p_text, decrypted_len);
}

void aes_cbc_encrypt(uint8_t* data_in, size_t data_in_size, char* encrypted_buffer, size_t* encrypted_data_size, uint8_t* key)
{
    ret_code_t  ret_val;
    uint8_t     iv[16];
    nrf_crypto_aes_context_t cbc_encr_128_ctx;
    
    /* Init encryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_encr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_ENCRYPT);
    AES_ERROR_CHECK(ret_val);
    
    /* Set key for encryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_encr_128_ctx, key);
    AES_ERROR_CHECK(ret_val);
    
    memset(iv, 0, sizeof(iv));
    /* Set IV for encryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_encr_128_ctx, iv);
    AES_ERROR_CHECK(ret_val);

    /* Encrypt text
       When padding is selected m_encrypted_text buffer shall be at least 16 bytes larger
       than text_len. */
    ret_val = nrf_crypto_aes_finalize(&cbc_encr_128_ctx,
                                      data_in,
                                      data_in_size,
                                      (uint8_t *)encrypted_buffer,
                                      encrypted_data_size);
    AES_ERROR_CHECK(ret_val);
}

void aes_cbc_decrypt(char* encrypted_data, size_t encrypted_data_size, char* decrypted_data, size_t* decrypted_data_size, uint8_t* key)
{
    ret_code_t  ret_val;
    uint8_t     iv[16];
    nrf_crypto_aes_context_t cbc_decr_128_ctx; // AES CBC decryption context


    /* Init decryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_decr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_DECRYPT);
    AES_ERROR_CHECK(ret_val);

    /* Set key for decryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, key);
    AES_ERROR_CHECK(ret_val);


    memset(iv, 0, sizeof(iv));
    /* Set IV for decryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, iv);
    AES_ERROR_CHECK(ret_val);

    /* Decrypt text */
    ret_val = nrf_crypto_aes_finalize(&cbc_decr_128_ctx,
                                      (uint8_t *)encrypted_data,
                                      encrypted_data_size,
                                      (uint8_t *)decrypted_data,
                                      decrypted_data_size);
    AES_ERROR_CHECK(ret_val);
}

int aes_data_validation(char* data, char* decryption, size_t len)
{
    return memcmp(data, decryption, len) == 0;
}

void ecdsa_sign(
    uint8_t* data, 
    size_t data_size, 
    nrf_crypto_ecdsa_secp256r1_signature_t signature_buffer, 
    size_t* signature_size, 
    uint8_t* raw_private_key, 
    size_t raw_private_key_size
)
{
    nrf_crypto_ecc_private_key_t private_key;
    ret_code_t                   err_code = NRF_SUCCESS;

    NRF_LOG_INFO("Gerando assinatura...");

     // Convert raw private key to internal representation
    err_code = nrf_crypto_ecc_private_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                   &private_key,
                                                   raw_private_key,
                                                   raw_private_key_size);
    DEMO_ERROR_CHECK(err_code);
   
    err_code = nrf_crypto_ecdsa_sign(NULL,
                                     &private_key,
                                     data,
                                     data_size,
                                     signature_buffer,
                                     signature_size);
    DEMO_ERROR_CHECK(err_code);

    // Free internal allocations
    err_code = nrf_crypto_ecc_private_key_free(&private_key);
    DEMO_ERROR_CHECK(err_code);
}

void ecdsa_verify(
    uint8_t* data, 
    size_t data_size,
    nrf_crypto_ecdsa_secp256r1_signature_t signature_buffer, 
    size_t signature_buffer_size, 
    uint8_t* raw_public_key,
    size_t raw_public_key_size
)
{
    nrf_crypto_ecc_public_key_t public_key;
    ret_code_t                  err_code = NRF_SUCCESS;

    NRF_LOG_INFO("Verificando assinatura...");

    // Convert raw bytes to public key internal representation
    err_code = nrf_crypto_ecc_public_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                  &public_key,
                                                  raw_public_key,
                                                  raw_public_key_size);
    DEMO_ERROR_CHECK(err_code);

    // Data signature verification
    err_code = nrf_crypto_ecdsa_verify(NULL,
                                       &public_key,
                                       data,
                                       data_size,
                                       signature_buffer,
                                       signature_buffer_size);
    
    if (err_code == NRF_SUCCESS)
    {
        NRF_LOG_INFO("Assinatura valida, o conteudo esta integro e autentico.");
    }
    else if (err_code == NRF_ERROR_CRYPTO_ECDSA_INVALID_SIGNATURE)
    {
        NRF_LOG_WARNING("Assinatura invalida, integridade e autenticidade da mensagem não pode ser verificada");
    }
    else
    {
        // Unpredicted error
        DEMO_ERROR_CHECK(err_code);
    }
}


float read_body_temperature()
{
    return 36.5;
}


uint16_t read_body_heartBeat()
{
    return 112;
}

uint8_t read_body_spo2()
{
    return 92;
}
