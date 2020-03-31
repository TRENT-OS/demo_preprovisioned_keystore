/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "RpcServerInit.h"

/* Defines -------------------------------------------------------------------*/
#define NVM_PARTITION_SIZE      (1024*128)
#define KEYSTORE_IV             "15e1f594c54670bf"
#define KEYSTORE_KEY_AES        "f131830db44c54742fc3f3265f0f1a0c"

/* Private functions ---------------------------------------------------------*/
static int entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    return 0;
}

/* Public functions -----------------------------------------------------------*/
bool keyStoreContext_ctor(KeyStoreContext*  keyStoreCtx,
                          uint8_t           channelNum,
                          void*             dataport)
{
    if (!ChanMuxNvmDriver_ctor(
            &(keyStoreCtx->chanMuxNvm),
            channelNum,
            dataport))
    {
        Debug_LOG_ERROR("%s: Failed to construct chanMuxNvm, channel %d!", __func__,
                        channelNum);
        return false;
    }

    static OS_Crypto_Config_t cfg =
    {
        .mode = OS_Crypto_MODE_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free   = free,
        },
        .impl.lib.rng = {
            .entropy = entropyFunc,
        },
    };

    if (OS_Crypto_init(&(keyStoreCtx->hCrypto), &cfg) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Failed to initialize the crypto, channel %d!",
                        __func__, channelNum);
        return 0;
    }

    static const OS_CryptoKey_Data_t masterKeyData =
    {
        .type = OS_CryptoKey_TYPE_AES,
        .data.aes.len = sizeof(KEYSTORE_KEY_AES)-1,
        .data.aes.bytes = KEYSTORE_KEY_AES
    };


    if (!AesNvm_ctor(&(keyStoreCtx->aesNvm),
                     ChanMuxNvmDriver_get_nvm(&(keyStoreCtx->chanMuxNvm)),
                     keyStoreCtx->hCrypto,
                     KEYSTORE_IV,
                     &masterKeyData))
    {
        Debug_LOG_ERROR("%s: Failed to initialize AesNvm, channel %d!", __func__,
                        channelNum);
        return false;
    }

    if (!SeosSpiffs_ctor(&(keyStoreCtx->fs), AesNvm_TO_NVM(&(keyStoreCtx->aesNvm)),
                         NVM_PARTITION_SIZE, 0))
    {
        Debug_LOG_ERROR("%s: Failed to initialize spiffs, channel %d!", __func__,
                        channelNum);
        return false;
    }

    seos_err_t ret = SeosSpiffs_mount(&(keyStoreCtx->fs));
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: spiffs mount failed with error code %d, channel %d!",
                        __func__, ret, channelNum);
        return false;
    }

    keyStoreCtx->fileStreamFactory = SpiffsFileStreamFactory_TO_FILE_STREAM_FACTORY(
                                         SpiffsFileStreamFactory_getInstance(&(keyStoreCtx->fs)));
    if (keyStoreCtx->fileStreamFactory == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to get the SpiffsFileStreamFactory instance, channel %d!",
                        __func__, channelNum);
        return false;
    }
    return true;
}

bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx)
{
    FileStreamFactory_dtor(keyStoreCtx->fileStreamFactory);
    SeosSpiffs_dtor(&(keyStoreCtx->fs));
    AesNvm_dtor(AesNvm_TO_NVM(&(keyStoreCtx->aesNvm)));
    OS_Crypto_free(keyStoreCtx->hCrypto);
    ChanMuxNvmDriver_dtor(&(keyStoreCtx->chanMuxNvm));

    return true;
}
