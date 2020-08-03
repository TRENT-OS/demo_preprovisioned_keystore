/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Keystore.h"

#include "LibDebug/Debug.h"

#include <stdlib.h>
#include <camkes.h>

#define AES_BLOCK_LEN       OS_CryptoCipher_SIZE_AES_BLOCK
// NVM setup
#define NVM_PARTITION_SIZE  (1024*128)
#define NVM_CHANNEL_NUM     (6)
#define NVM_DATAPORT        chanMuxDataPort
// Encryption key for pre-provisioned partition
#define KEYSTORE_IV         "15e1f594c54670bf"
#define KEYSTORE_KEY_AES    "f131830db44c54742fc3f3265f0f1a0c"
#define KEYSTORE_NAME       "KEY_STORE"
// Key names
#define AES_KEY1_NAME       "AESKeyImported"
#define AES_KEY2_NAME       "AESKeyGenerated"
#define RSA_PRV_KEY_NAME    "RSAKeyPrv"
#define RSA_PUB_KEY_NAME    "RSAKeyPub"
#define DH_PRV_KEY_NAME     "DHKeyPrv"
#define DH_PUB_KEY_NAME     "DHKeyPub"

typedef struct
{
    OS_FileSystem_Handle_t hFs;
} testRunner_ctx_t;

// Use the EntropySource provided with TRENTOS-M
static OS_Crypto_Config_t cfgLocal =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
    .library.entropy = OS_CRYPTO_ASSIGN_Entropy(
        entropy_rpc,
        entropy_port),
};

// Config for FileSystem API
static const OS_FileSystem_Config_t cfgFs =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_STORAGE_MAX,
    .storage = OS_FILESYSTEM_ASSIGN_Storage(
        storage_rpc,
        storage_port),
};

// Private functions -----------------------------------------------------------
static OS_Error_t
initFileSystem(
    OS_FileSystem_Handle_t* hFs)
{
    OS_Error_t err;

    if ((err = OS_FileSystem_init(hFs, &cfgFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_init() failed with %d", err);
        return err;
    }

    // Try mounting, if it fails we format the disk again and try another time
    if ((err = OS_FileSystem_mount(*hFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_mount() finally failed with %d", err);
        return err;
    }

    return OS_SUCCESS;
}


static OS_Error_t
runDemo(
    OS_Crypto_Handle_t   hCrypto,
    OS_Keystore_Handle_t hKeystore)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    OS_CryptoKey_Data_t keyData;
    OS_CryptoKey_Handle_t hKey;
    size_t keyLen;

    /***************************** AES key 1 *******************************/
    keyLen = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, AES_KEY1_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey() failed with err %d", err);
    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import() failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free() failed with err %d", err);

    /***************************** AES key 2 *******************************/
    keyLen = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, AES_KEY1_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey() failed with err %d", err);
    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import() failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free() failed with err %d", err);

    /***************************** RSA private key *******************************/
    keyLen = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, RSA_PRV_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey() failed with err %d", err);
    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import() failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free() failed with err %d", err);

    /***************************** RSA public key *******************************/
    keyLen = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, RSA_PUB_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey() failed with err %d", err);
    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import() failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free() failed with err %d", err);

    /***************************** DH private key *******************************/
    keyLen = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, DH_PRV_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey() failed with err %d", err);
    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import() failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free() failed with err %d", err);

    /***************************** DH public key *******************************/
    keyLen = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, DH_PUB_KEY_NAME, &keyData, &keyLen);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey() failed with err %d", err);
    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import() failed with err %d", err);
    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free() failed with err %d", err);

    return OS_SUCCESS;
}

// Public functions -----------------------------------------------------------
int run()
{
    OS_Error_t err = OS_ERROR_GENERIC;
    OS_Crypto_Handle_t hCrypto;
    OS_Keystore_Handle_t hKeystore;
    OS_FileSystem_Handle_t hFs;

    // Setup Crypto
    err = OS_Crypto_init(&hCrypto, &cfgLocal);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Crypto_init() failed with error code %d!", err);
    // Setup FileSystem
    err = initFileSystem(&hFs);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "initFileSystem() failed with error code %d!", err);
    // Setup keystore
    err = OS_Keystore_init(&hKeystore, hFs, hCrypto, KEYSTORE_NAME);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_init() failed with error code %d!", err);

    // Run demo
    err = runDemo(hCrypto, hKeystore);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: runDemo() failed with error code %d!", __func__, err);
        return err;
    }

    // Tear down everything
    err = OS_Keystore_free(hKeystore);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_free() failed with error code %d!", err);

    err = OS_Crypto_free(hCrypto);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Crypto_free() failed with error code %d!", err);

    Debug_LOG_INFO("\n\nPreprovisioning keystore demo succeeded!\n");

    return 0;
}