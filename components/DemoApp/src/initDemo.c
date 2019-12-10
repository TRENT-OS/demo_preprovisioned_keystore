/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "initDemo.h"

#include "LibDebug/Debug.h"

#include "camkes.h"

seos_err_t initDemo(SeosCryptoRpcClient* cryptoApi, SeosKeyStoreClient* keyStoreApi)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    /***************************** Init crypto *******************************/
    SeosCryptoApi_RpcServer cryptoRpcHandle = NULL;

    err = Crypto_getRpcHandle(&cryptoRpcHandle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Crypto_getRpcHandle failed with error code %d!",
                        __func__, err);
        return err;
    }

    err = SeosCryptoRpcClient_init(cryptoApi, cryptoRpcHandle, cryptoClientDataport);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoRpcClient_init failed with error code %d!",
                        __func__, err);
        return err;
    }

    /***************************** Init KeyStore *******************************/
    SeosKeyStoreRpc_Handle keyStoreRpcHandle = NULL;

    err = KeyStore_getRpcHandle(&keyStoreRpcHandle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: KeyStore_getRpcHandle failed with error code %d!",
                        __func__, err);
        return err;
    }

    err = SeosKeyStoreClient_init(keyStoreApi, keyStoreRpcHandle, keyStoreClientDataport);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreClient_init failed with error code %d!",
                        __func__, err);
        return err;
    }

    return err;
}