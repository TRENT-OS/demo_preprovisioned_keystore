/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "initDemo.h"

#include "LibDebug/Debug.h"

#include "camkes.h"

seos_err_t initDemo(SeosCryptoApi* cryptoApi, SeosKeyStoreClient* keyStoreApi)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoApi_Config cfgRemote =
    {
        .mode = SeosCryptoApi_Mode_RPC_CLIENT,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.client.dataPort = cryptoClientDataport
    };

    /***************************** Init crypto *******************************/
    err = Crypto_openSession(&cfgRemote.impl.client.api);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "Crypto_openSession failed with error code %d!", err);
    err = SeosCryptoApi_init(cryptoApi, &cfgRemote);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_init failed with error code %d!", err);

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