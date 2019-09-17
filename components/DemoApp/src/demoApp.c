/**
 * @addtogroup PreprovisioninedKeyStore_Demo_App
 * @{
 *
 * @file demoApp.c
 *
 * @brief demo application that showcases the key store functionalities 
 * by using a pre-created keystore image that contains 2 keys
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#include "LibDebug/Debug.h"

#include "SeosCryptoClient.h"
#include "SeosKeyStoreClient.h"

#include "SeosCryptoApi.h"
#include "SeosKeyStoreApi.h"

#include "initDemo.h"

#include <camkes.h>

/* Defines -------------------------------------------------------------------*/
#define NVM_PARTITION_SIZE      (1024*128)
#define AES_BLOCK_LEN           16

#define KEY1_NAME   "MasterKey1"
#define KEY2_NAME   "MasterKey2"

//Sample encryption/decryption data
#define SAMPLE_STRING   "0123456789ABCDEF"

/* Private functions prototypes ----------------------------------------------*/
static seos_err_t
aesEncrypt(SeosCryptoCtx* cryptoCtx,
           SeosCrypto_KeyHandle keyHandle,
           const char* data,
           size_t inDataSize,
           void** outBuf,
           size_t* outDataSize);

static seos_err_t
aesDecrypt(SeosCryptoCtx* cryptoCtx,
           SeosCrypto_KeyHandle keyHandle,
           const void* data,
           size_t inDataSize,
           void** outBuf,
           size_t* outDataSize);

static seos_err_t runDemo(SeosCryptoCtx* cryptoApi, SeosKeyStoreCtx* keyStoreApi);

/**
 * @weakgroup KeyStorePreprovisioningDemo
 * @{
 * 
 * @brief Top level preprovisioning demo
 *
 * @test \b KeyStorePreprovisioningDemo_version_1   \n 1) Open 2 keys that should already be present in the keystore (the keys have the same key material)
 *                                                  \n 2) Use one key to encrypt the sample string
 *                                                  \n 3) Use the other key to decrypt the previously encrypted string
 *                                                  \n 4) Verify that the decrypted string is equal to the initial one
 *                                                  \n 5) Delete both keys
 * @}
 */

/* Main ----------------------------------------------------------------------*/
int run()
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoClient cryptoApi;
    SeosKeyStoreClient keyStoreApi;

    /***************************** Initialization ****************************/
    err = initDemo(&cryptoApi, &keyStoreApi);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: initDemo failed with error code %d!", __func__, err);
        return err;
    }

    /***************************** DEMO APP **********************************/
    err = runDemo(&cryptoApi.parent, &keyStoreApi.parent);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: runDemo failed with error code %d!", __func__, err);
        return err;
    }

    /***************************** Destruction *******************************/
    SeosCryptoClient_deInit(&cryptoApi.parent);
    SeosKeyStoreClient_deInit(&keyStoreApi.parent);

    Debug_LOG_INFO("\n\nPreprovisioning keystore demo succeeded!\n");

    return 0;
}

/* Private functions -----------------------------------------------------------*/
static seos_err_t runDemo(SeosCryptoCtx* cryptoApi, SeosKeyStoreCtx* keyStoreApi)
{
    SeosCrypto_KeyHandle key1;
    SeosCrypto_KeyHandle key2;

    seos_err_t err = SEOS_ERROR_GENERIC;

    char buffEnc[AES_BLOCK_LEN] = {0};
    char buffDec[AES_BLOCK_LEN] = {0};
    void* outputEncrypt = &buffEnc;
    void* outputDecrypt = &buffDec;
    size_t decOutSize = 0;
    size_t encOutSize = 0;

    //open the key 1
    err = SeosKeyStoreApi_getKey(keyStoreApi, &key1, KEY1_NAME);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreApi_getKey failed with error code %d!",
                        __func__, err);
        return err;
    }

    //open the key 2
    err = SeosKeyStoreApi_getKey(keyStoreApi, &key2, KEY2_NAME);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreApi_getKey failed with error code %d!",
                        __func__, err);
        return err;
    }

    // use key1 for aes encryption
    err = aesEncrypt(cryptoApi, key1, SAMPLE_STRING,
                                strlen(SAMPLE_STRING), &outputEncrypt, &decOutSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: aesEncrypt failed with error code %d",
                        __func__, err);
        return err;
    }

    // use key2 to decrypt the previously encrypted buffer
    err = aesDecrypt(cryptoApi, key2, outputEncrypt, decOutSize,
                     &outputDecrypt, &encOutSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: aesDecrypt failed with error code %d",
                        __func__, err);
        return err;
    }

    // check if the decrypted string is the same as the original string
    if (strncmp(SAMPLE_STRING, ((char*)outputDecrypt), AES_BLOCK_LEN) != 0)
    {
        Debug_LOG_ERROR("%s: AES encryption/decryption failed! Decrypted block: %s, original block: %s",
                        __func__, ((char*)outputDecrypt), SAMPLE_STRING);
        return SEOS_ERROR_GENERIC;
    }

    // delete key1 after usage
    err = SeosKeyStoreApi_deleteKey(key1);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreApi_deleteKey failed with error code %d!",
                        __func__, err);
        return err;
    }

    // delete key2 after usage
    err = SeosKeyStoreApi_deleteKey(key2);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreApi_deleteKey failed with error code %d!",
                        __func__, err);
        return err;
    }
    
    return err;
}

static seos_err_t
aesEncrypt(SeosCryptoCtx* cryptoCtx, SeosCrypto_KeyHandle keyHandle,
           const char* data, size_t inDataSize, void** outBuf, size_t* outDataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle handle;

    *outDataSize = AES_BLOCK_LEN;

    err = SeosCryptoApi_cipherInit(cryptoCtx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC,
                                   keyHandle,
                                   NULL, 0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherInit failed with error code %d",
                        __func__, err);
        return err;
    }

    err = SeosCryptoApi_cipherUpdate(cryptoCtx,
                                     handle,
                                     data,
                                     inDataSize,
                                     outBuf,
                                     outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherUpdate failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_cipherClose(cryptoCtx, handle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherClose failed with error code %d",
                        __func__, err);
    }

    return err;
}

static seos_err_t
aesDecrypt(SeosCryptoCtx* cryptoCtx, SeosCrypto_KeyHandle keyHandle,
           const void* data, size_t inDataSize, void** outBuf, size_t* outDataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle handle;

    *outDataSize = AES_BLOCK_LEN;

    err = SeosCryptoApi_cipherInit(cryptoCtx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC,
                                   keyHandle,
                                   NULL, 0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherInit failed with error code %d",
                        __func__, err);
        return err;
    }

    err = SeosCryptoApi_cipherUpdate(cryptoCtx,
                                     handle,
                                     data,
                                     inDataSize,
                                     outBuf,
                                     outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherUpdate failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_cipherClose(cryptoCtx, handle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherClose failed with error code %d",
                        __func__, err);
    }

    return err;
}

///@}
