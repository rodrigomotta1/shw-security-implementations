#ifndef UTILS_HEADER
#define UTILS_HEADER

#include <stdint.h>
#include <stddef.h>
#include "nrf_crypto_ecdsa.h"


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


#define DEMO_ERROR_CHECK(error)     \
do                                  \
{                                   \
    if (error != NRF_SUCCESS)       \
    {                               \
        NRF_LOG_ERROR("Error 0x%04X: %s", error, nrf_crypto_error_string_get(error));\
        APP_ERROR_CHECK(error);     \
    }                               \
} while(0)


enum MessageTypes {
    MTYPE_SYNC,
    MTYPE_DATA
};

struct data_packet {
    uint64_t    uuid[2];        // Identificador do dispostivo mandando a mensagem
    float       temperature;    // Temperatura corporal do usuário
    uint16_t    heartRate;      // Frequência cardíaca do usuário
    uint8_t     spo2;           // Saturação de oxigêncio do usuário
    uint8_t     button;         // Indicador de pressionamento do botão no dispositivo
    //uint16_t    m_uid;          // Identificador do pacote de mensagem. Importante para o caso onde a basestation receba a msg mas o wearable nao receba o ack. Nesse caso, o wearable enviaria a mensagem de novo e a basestation anotaria como um nova msg
    uint8_t     msgType;        // Tipo de mensagem (MTYPE_SYNC ou MTYPE_DATA)
};

typedef struct data_packet DataPacket;


/**
 * @brief Print formatted a DataPacket struct
 * 
 * @param p_label Text label to be printed out before actual struct data
 * @param p_struct Pointer to DataPacket struct
*/
void struct_print(char const* p_label, DataPacket* p_struct);


/**
 * @brief Print string formatted (test purposes)
 * 
 * @param p_label Text label to be printed out before actual text
 * @param p_text String that will be printed
 * @param len Length of string that will be printed
*/
void text_print(char const* p_label, char const * p_text, size_t len);


/**
 * @brief Print hexadecimal representation of string or bytes from uint8_t array.
 *        To print bytes, pass a casted uint8_t array of any type (check)
 * 
 * @param p_label Text label to be printed out before actual content
 * @param p_text String from where bytes will be printed
 * @param len Length of string that bytes came from
*/
void hex_text_print(char const* p_label, char const * p_text, size_t len);


/**
 * @brief Print struct contents followed by bytes representation
 * 
 * @param ptr_packet Pointer to DataPacket value
*/
void plain_text_print(DataPacket* ptr_packet);


/**
 * @brief Print encrypted bytes
 * 
 * @param p_text Pointer to array where encrypted content is stored
 * @param encrypted_len Size of encrypted array
*/
void encrypted_text_print(char const * p_text, size_t encrypted_len);

/**
 * @brief Print decrypted struct contents followed by bytes representation
 * 
 * @param p_text Pointer to array where decrypted content is stored
 * @param decrypted_len Size of decrypted array
*/
void decrypted_text_print(char const * p_text, size_t decrypted_len);


/**
 * @brief Stores the result of AES CBC encryption into a buffer
 * 
 * @note IV must be predefined as a true random value
 * 
 * @param data_in Pointer to array of bytes to be encrypted
 * @param data_in_size Number of bytes in the array
 * @param encrypted_buffer Char array where encryption result (bytes) will be stored
 * @param encrypted_data_size Pointer to variable where encrypted data size will be stored after encryption (encrypted data size is unknown before the encryption routine))
 * @param key Array containing bytes from AES used key
*/
void aes_cbc_encrypt(uint8_t* data_in, size_t data_in_size, char* encrypted_buffer, size_t* encrypted_data_size, uint8_t* key);


/**
 * @brief Stores the result of AES CBC descyption into a buffer
 * 
 * @note IV must be predefined as a true random value
 * 
 * @param encrypted_data Char array with encrypted bytes
 * @param encrypted_data_size Number of bytes of encrypted data. This is gathered from the result of encryption (&len_out)
 * @param decrypted_data Char array where decryption result (text) will be stored
 * @param decrypted_data_size Pointer to variable that will store resulting number of bytes from decryption
 * @param key Array containing bytes from AES used key
*/
void aes_cbc_decrypt(char* encrypted_data, size_t encrypted_data_size, char* decrypted_data, size_t* decrypted_data_size, uint8_t* key);


/**
 * @brief Verifies if decrypted data matches with original data
 * 
 * @param data Original data bytes array
 * @param decryption Decrypted data bytes array
 * @param len Length of original data
*/
int aes_data_validation(char* data, char* decryption, size_t len);

void ecdsa_sign(uint8_t* data, 
    size_t data_size, 
    nrf_crypto_ecdsa_secp256r1_signature_t signature_buffer, 
    size_t* signature_size, 
    uint8_t* raw_private_key, 
    size_t raw_private_key_size);

void ecdsa_verify(uint8_t* data, 
    size_t data_size,
    nrf_crypto_ecdsa_secp256r1_signature_t signature_buffer, 
    size_t signature_buffer_size, 
    uint8_t* raw_public_key,
    size_t raw_public_key_size);

float read_body_temperature();
uint16_t read_body_heartBeat();
uint8_t read_body_spo2();


#endif