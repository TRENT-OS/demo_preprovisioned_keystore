/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "OS_Crypto.h"
#include "OS_Keystore.h"

#include "ChanMuxNvmDriver.h"
#include "AesNvm.h"
#include "OS_Spiffs.h"
#include "SpiffsFileStreamFactory.h"

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
    ChanMuxNvmDriver chanMuxNvm;
    AesNvm aesNvm;
    OS_Spiffs_t spiffs;
    FileStreamFactory* fileStreamFactory;
} FS_Context_t;

static OS_CryptoKey_Data_t masterKeyData =
{
    .type = OS_CryptoKey_TYPE_AES,
    .data.aes.len = sizeof(KEYSTORE_KEY_AES) - 1,
    .data.aes.bytes = KEYSTORE_KEY_AES
};
static OS_Crypto_Config_t cfgLocal =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
};

// Private functions -----------------------------------------------------------
static int
entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // NOTE: Requires entropy from PLATFORM!
    return 0;
}

static OS_Error_t
initFs(
    FS_Context_t*       ctx,
    OS_Crypto_Handle_t  hCrypto,
    FileStreamFactory** fs)
{
    OS_Error_t err;

    err = OS_ERROR_GENERIC;

    if (!ChanMuxNvmDriver_ctor(&ctx->chanMuxNvm, NVM_CHANNEL_NUM, NVM_DATAPORT))
    {
        Debug_LOG_ERROR("%s: Failed to construct chanMuxNvm, channel %d!", __func__,
                        NVM_CHANNEL_NUM);
        return err;
    }
    if (!AesNvm_ctor(&ctx->aesNvm, ChanMuxNvmDriver_get_nvm(&ctx->chanMuxNvm),
                     hCrypto, KEYSTORE_IV, &masterKeyData))
    {
        Debug_LOG_ERROR("%s: Failed to initialize AesNvm, channel %d!", __func__,
                        NVM_CHANNEL_NUM);
        goto err0;
    }
    if (!OS_Spiffs_ctor(&ctx->spiffs, AesNvm_TO_NVM(&ctx->aesNvm),
                         NVM_PARTITION_SIZE, 0))
    {
        Debug_LOG_ERROR("%s: Failed to initialize spiffs, channel %d!", __func__,
                        NVM_CHANNEL_NUM);
        goto err1;
    }
    if ((err = OS_Spiffs_mount(&ctx->spiffs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_Spiffs_mount() failed with error code %d, channel %d!",
                        __func__, err, NVM_CHANNEL_NUM);
        goto err1;
    }

    *fs = SpiffsFileStreamFactory_TO_FILE_STREAM_FACTORY(
              SpiffsFileStreamFactory_getInstance(&ctx->spiffs));
    if (NULL == *fs)
    {
        Debug_LOG_ERROR("%s: Failed to get the SpiffsFileStreamFactory instance, channel %d!",
                        __func__, NVM_CHANNEL_NUM);
        err = OS_ERROR_GENERIC;
        goto err2;
    }

    return OS_SUCCESS;

err2:
    OS_Spiffs_dtor(&ctx->spiffs);
err1:
    AesNvm_dtor(AesNvm_TO_NVM(&ctx->aesNvm));
err0:
    ChanMuxNvmDriver_dtor(&ctx->chanMuxNvm);

    return err;
}

static OS_Error_t
freeFs(
    FS_Context_t*      ctx,
    FileStreamFactory* fs)
{
    SpiffsFileStreamFactory_dtor(fs);
    OS_Spiffs_dtor(&ctx->spiffs);
    AesNvm_dtor(AesNvm_TO_NVM(&ctx->aesNvm));
    ChanMuxNvmDriver_dtor(&ctx->chanMuxNvm);

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
    FS_Context_t ctx;
    FileStreamFactory* fs;

    // Setup Crypto
    cfgLocal.library.rng.entropy = entropyFunc;
    err = OS_Crypto_init(&hCrypto, &cfgLocal);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Crypto_init() failed with error code %d!", err);
    // We use the crypto also for encryption of the NVM
    err = initFs(&ctx, hCrypto, &fs);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "initFs() failed with error code %d!", err);
    // Setup keystore
    err = OS_Keystore_init(&hKeystore, fs, hCrypto, KEYSTORE_NAME);
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
    err = freeFs(&ctx, fs);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "freeFs() failed with error code %d!", err);
    err = OS_Crypto_free(hCrypto);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Crypto_free() failed with error code %d!", err);

    Debug_LOG_INFO("\n\nPreprovisioning keystore demo succeeded!\n");

    return 0;
}