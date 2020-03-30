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

#include "SeosKeyStoreClient.h"

#include "OS_Crypto.h"
#include "SeosKeyStoreApi.h"

#include "initDemo.h"

#include <camkes.h>

/* Defines -------------------------------------------------------------------*/
#define NVM_PARTITION_SIZE      (1024*128)
#define AES_BLOCK_LEN           16

#define AES_KEY1_NAME       "AESKeyImported"
#define AES_KEY2_NAME       "AESKeyGenerated"
#define RSA_PRV_KEY_NAME    "RSAKeyPrv"
#define RSA_PUB_KEY_NAME    "RSAKeyPub"
#define DH_PRV_KEY_NAME     "DHKeyPrv"
#define DH_PUB_KEY_NAME     "DHKeyPub"

//Sample encryption/decryption data
#define SAMPLE_STRING   "0123456789ABCDEF"

/* Static variables------------------------------------------------------------*/
static OS_CryptoKey_Data_t keyData;

/* Private functions prototypes ----------------------------------------------*/
static seos_err_t runDemo(OS_Crypto_Handle_t hCrypto,
                          SeosKeyStoreCtx* keyStoreApi);

/**
 * @weakgroup KeyStorePreprovisioningDemo
 * @{
 *
 * @brief Top level preprovisioning demo that tries to fetch
 * pre-provisioned keys from the keystore (assuming they are there)
 * and verifies their validity by importing them back in the crypto api
 *
 * @test \b KeyStorePreprovisioningDemo     \n 1) Fetch AESKeyImported and import it to the crypto api
 *                                          \n 2) Fetch AESKeyGenerated and import it to the crypto api
 *                                          \n 3) Fetch RSAKeyPrv and import it to the crypto api
 *                                          \n 4) Fetch RSAKeyPub and import it to the crypto api
 *                                          \n 5) Fetch DHKeyPrv and import it to the crypto api
 *                                          \n 6) Fetch DHKeyPub and import it to the crypto api
 * @}
 */

/* Main ----------------------------------------------------------------------*/
int run()
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_Crypto_Handle_t hCrypto;
    SeosKeyStoreClient keyStoreApi;

    /***************************** Initialization ****************************/
    err = initDemo(&hCrypto, &keyStoreApi);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: initDemo failed with error code %d!", __func__, err);
        return err;
    }

    /***************************** DEMO APP **********************************/
    err = runDemo(hCrypto, &keyStoreApi.parent);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: runDemo failed with error code %d!", __func__, err);
        return err;
    }

    /***************************** Destruction *******************************/
    OS_Crypto_free(hCrypto);
    SeosKeyStoreClient_deInit(&keyStoreApi.parent);

    Debug_LOG_INFO("\n\nPreprovisioning keystore demo succeeded!\n");

    return 0;
}

/* Private functions -----------------------------------------------------------*/
static seos_err_t runDemo(OS_Crypto_Handle_t hCrypto,
                          SeosKeyStoreCtx* keyStoreApi)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoKey_Handle_t hKey;
    size_t keyLen;

    /***************************** AES key 1 *******************************/
    keyLen = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreApi, AES_KEY1_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /***************************** AES key 2 *******************************/
    keyLen = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreApi, AES_KEY1_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /***************************** RSA private key *******************************/
    keyLen = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreApi, RSA_PRV_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /***************************** RSA public key *******************************/
    keyLen = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreApi, RSA_PUB_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /***************************** DH private key *******************************/
    keyLen = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreApi, DH_PRV_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /***************************** DH public key *******************************/
    keyLen = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreApi, DH_PUB_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    return SEOS_SUCCESS;
}

///@}
