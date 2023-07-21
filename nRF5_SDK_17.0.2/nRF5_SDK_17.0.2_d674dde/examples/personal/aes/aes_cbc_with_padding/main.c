/**
 * Copyright (c) 2018 - 2020, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <ctype.h>

#include <stdint.h>


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


#if NRF_MODULE_ENABLED(NRF_CRYPTO)
/**@file
 * @defgroup AES_CBC_with_padding_example main.c
 *
 * @{
 *
 */

#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE 120


#define AES_ERROR_CHECK(error)  \
    do {            \
        if (error)  \
        {           \
            NRF_LOG_RAW_INFO("\r\nError = 0x%x\r\n%s\r\n",           \
                             (error),                                \
                             nrf_crypto_error_string_get(error));    \
            return; \
        }           \
    } while (0);


enum MessageTypes {
  MTYPE_SYNC,
  MTYPE_DATA
};

struct data_packet {
  uint64_t uuid[2];     //uuid do wearable que enviou msg
  float temperature;
  uint16_t heartRate;
  uint8_t spo2;
  uint8_t button;
  //uint16_t m_uid;     //uid da mensagem. Importante para o caso onde a basestation receba a msg mas o wearable nao receba o ack. Nesse caso, o wearable enviaria a mensagem de novo e a basestation anotaria como um nova msg
  uint8_t msgType;
};

typedef struct data_packet DataPacket;

const uint64_t WKIT_UUID[] = {0xbf4ce634e1484540, 0x83dd7b0616f0709a}; //"bf4ce634-e148-4540-83dd-7b0616f0709a"



/* Maximum allowed key = 256 bit */
//static uint8_t m_key[32] = {'N', 'O', 'R', 'D', 'I', 'C', ' ',
                            //'S', 'E', 'M', 'I', 'C', 'O', 'N', 'D', 'U', 'C', 'T', 'O', 'R',
                            //'A', 'E', 'S', ' ', 'C', 'B', 'C', ' ', 'T', 'E', 'S', 'T'};

// Random key generated with pwgen
static uint8_t m_key[32] = {
  'v', 'e', '3', 'e', 'i', 'X', 'o', 'h', '9',
  'a', 'e', '3', 'g', 'o', 'i', 'p', 'h', 'o',
  'e', 'z', 'a', 'e', 'T', 'h', 'a', 'e', 'k',
  'e', 'B', 'a', 'e', 'g'
};

/* Below text is used as plain text for encryption and decryption in AES CBC mode with padding. */
static char m_plain_text[] =
{
    "Example string to demonstrate AES CBC mode with padding. This text has 85 characters."
};

static void struct_print(char const* p_label, struct data_packet* p_struct)
{
    NRF_LOG_RAW_INFO("----%s (size: %u) ----\r\n", p_label, sizeof(struct data_packet));
    NRF_LOG_FLUSH();
    NRF_LOG_RAW_INFO("Temp: %.1f\nFreq: %d\nSPO2: %d\n", p_struct->temperature, p_struct->heartRate, p_struct->spo2);
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("----%s (len: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();
    for(size_t i = 0; i < len; i++)
    {
        NRF_LOG_RAW_INFO("%c", p_text[i]);
        NRF_LOG_FLUSH();
    }
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void hex_text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("---- %s (len: %u) ----\r\n", p_label, len);
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
    NRF_LOG_RAW_INFO("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void plain_text_print(uint8_t * ptr_packet)
{
    //text_print("Plain text", (char*)ptr_example_packet, strlen((char*)ptr_example_packet));
    struct_print("Plain text", (struct data_packet*)ptr_packet);
    hex_text_print("Plain text (hex)", ptr_packet, (size_t)32);
}

static void encrypted_text_print(char const * p_text, size_t encrypted_len)
{
    hex_text_print("Encrypted text (hex)", p_text, encrypted_len);
}

static void decrypted_text_print(char const * p_text, size_t decrypted_len)
{
    //text_print("Decrypted text", p_text, decrypted_len);
    struct_print("Plain text", (struct data_packet*)p_text);
    hex_text_print("Decrypted text (hex)", p_text, decrypted_len);
}

static void crypt_cbc(void)
{
    uint8_t     iv[16];
    ret_code_t  ret_val;
    size_t      len_in;
    size_t      len_out;

    static char encrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
    static char decrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];

    static nrf_crypto_aes_context_t cbc_encr_128_ctx; // AES CBC encryption context
    static nrf_crypto_aes_context_t cbc_decr_128_ctx; // AES CBC decryption context

    DataPacket example_packet = {
        .uuid = {0xbf4ce634e1484540, 0x83dd7b0616f0709a},
        .temperature = 36.5, 
        .heartRate = 101, 
        .spo2 = 99, 
        .button = 0, 
        .msgType = MTYPE_DATA
    };

    uint8_t* ptr_example_packet = (uint8_t *) &example_packet; // Refer to this to print, enc and dec

    // Print goes wrong because bytes are in inversed order from they were supposed to be read (endianness confusion)
    plain_text_print((uint8_t*)&example_packet);

    memset(encrypted_text,  0, sizeof(encrypted_text));
    memset(decrypted_text,  0, sizeof(decrypted_text));

    //
    // Encryption phase
    //

    /* Init encryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_encr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_ENCRYPT);
    AES_ERROR_CHECK(ret_val);

    /* Set key for encryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_encr_128_ctx, m_key);
    AES_ERROR_CHECK(ret_val);

    memset(iv, 0, sizeof(iv));
    /* Set IV for encryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_encr_128_ctx, iv);
    AES_ERROR_CHECK(ret_val);

    len_in = (size_t)32;
    len_out = sizeof(encrypted_text);
    printf("tamanho: %d \n", len_out);

    /* Encrypt text
       When padding is selected m_encrypted_text buffer shall be at least 16 bytes larger
       than text_len. */
    ret_val = nrf_crypto_aes_finalize(&cbc_encr_128_ctx,
                                      ptr_example_packet,
                                      len_in,
                                      (uint8_t *)encrypted_text,
                                      &len_out);
    AES_ERROR_CHECK(ret_val);

    // print the encrypted text
    encrypted_text_print(encrypted_text, len_out);

    //
    // Decryption phase
    //

    /* Init decryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_decr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_DECRYPT);
    AES_ERROR_CHECK(ret_val);


    /* Set key for decryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, m_key);
    AES_ERROR_CHECK(ret_val);

    memset(iv, 0, sizeof(iv));
    /* Set IV for decryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, iv);
    AES_ERROR_CHECK(ret_val);

    /* Decrypt text */
    ret_val = nrf_crypto_aes_finalize(&cbc_decr_128_ctx,
                                      (uint8_t *)encrypted_text,
                                      len_out,
                                      (uint8_t *)decrypted_text,
                                      &len_out);
    AES_ERROR_CHECK(ret_val);

    /* trim padding */
    decrypted_text[len_out] = '\0';

    decrypted_text_print(decrypted_text, len_out);

    NRF_LOG_FLUSH();
    if (memcmp((char*)ptr_example_packet, decrypted_text, strlen((char*)ptr_example_packet)) == 0)
    {
        NRF_LOG_RAW_INFO("AES CBC example with padding executed successfully.\r\n");
    }
    else
    {
        NRF_LOG_RAW_INFO("AES CBC example with padding failed!!!\r\n");
    }
}

int main(void)
{
    

    ret_code_t ret;

    APP_ERROR_CHECK(NRF_LOG_INIT(NULL));
    NRF_LOG_DEFAULT_BACKENDS_INIT();

    NRF_LOG_RAW_INFO("sizeof struct data_packet is %d bytes\n", sizeof(struct data_packet));
    NRF_LOG_FLUSH();

    NRF_LOG_RAW_INFO("AES CBC example with padding started.\r\n\r\n");
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

    crypt_cbc();

    while (true)
    {
        NRF_LOG_FLUSH();
        UNUSED_RETURN_VALUE(NRF_LOG_PROCESS());
    }
}

/** @} */
#endif // NRF_MODULE_ENABLED(NRF_CRYPTO)

