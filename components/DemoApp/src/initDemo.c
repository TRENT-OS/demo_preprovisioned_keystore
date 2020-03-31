/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "initDemo.h"

#include "LibDebug/Debug.h"

#include "camkes.h"

seos_err_t initDemo(OS_Crypto_Handle_t* hCrypto, SeosKeyStoreClient* keyStoreApi)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_Crypto_Config_t cfgRemote =
    {
        .mode = OS_Crypto_MODE_RPC_CLIENT,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.client.dataPort = cryptoClientDataport
    };

    /***************************** Init crypto *******************************/
    err = CryptoRpcServer_openSession();
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "CryptoRpcServer_openSession failed with error code %d!", err);
    err = OS_Crypto_init(hCrypto, &cfgRemote);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_Crypto_init failed with error code %d!", err);

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
