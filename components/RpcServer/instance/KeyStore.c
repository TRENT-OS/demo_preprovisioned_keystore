/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "LibDebug/Debug.h"

#include "RpcServerInit.h"
#include "SeosCryptoApi.h"
#include <camkes.h>

static int entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    return 0;
}

seos_err_t
KeyStore_getRpcHandle(SeosKeyStoreRpc_Handle* instance)
{
    static SeosKeyStore keyStore;
    static SeosKeyStoreRpc the_one;
    static KeyStoreContext keyStoreCtx;
    static SeosCryptoApi_Config cfg =
    {
        .mode = SeosCryptoApi_Mode_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free   = free,
        },
        .impl.lib.rng = {
            .entropy = entropyFunc,
        },
    };
    SeosCryptoApiH hCrypto;

    if (SeosCryptoApi_init(&hCrypto, &cfg) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Failed to initialize the crypto!", __func__);
        return 0;
    }

    if (!keyStoreContext_ctor(&keyStoreCtx, 6, (void*)chanMuxDataPort))
    {
        Debug_LOG_ERROR("%s: Failed to initialize the test!", __func__);
        return 0;
    }

    seos_err_t retval = SeosKeyStore_init(&keyStore,
                                          keyStoreCtx.fileStreamFactory,
                                          hCrypto,
                                          "KEY_STORE");

    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStore_init failed with error code %d!", __func__,
                        retval);
        return retval;
    }


    retval = SeosKeyStoreRpc_init(&the_one, &(keyStore.parent),
                                  keyStoreServerDataport);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_init failed with error code %d!", __func__,
                        retval);
        return retval;
    }

    *instance = &the_one;

    if (SEOS_SUCCESS == retval)
    {
        Debug_LOG_TRACE("%s: created rpc object %p", __func__, *instance);
    }

    return retval;
}

void
KeyStore_closeRpcHandle(SeosKeyStoreRpc_Handle instance)
{
    /// TODO
}
