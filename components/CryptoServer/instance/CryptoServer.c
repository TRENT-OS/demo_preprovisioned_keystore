/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "LibDebug/Debug.h"

#include "CryptoServer.h"
#include "CryptoServerInit.h"
#include "SeosCryptoApi.h"
#include <camkes.h>

static SeosCryptoApi* cryptoInst;

static int dummyEntropyFunc(void* ctx, unsigned char* buf, size_t len);

seos_err_t
Crypto_openSession(
    SeosCryptoApi_Ptr* api)
{
    seos_err_t err;
    SeosCryptoApi_Config cfg =
    {
        .mode = SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free   = free,
        },
        .impl.lib.rng = {
            .entropy = dummyEntropyFunc,
            .context = NULL
        },
        .server.dataPort = cryptoServerDataport
    };

    if ((cryptoInst = malloc(sizeof(SeosCryptoApi))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    err = SeosCryptoApi_init(cryptoInst, &cfg);
    Debug_LOG_TRACE("SeosCryptoApi_init failed with %d", err);

    *api = cryptoInst;

    return err;
}

seos_err_t
Crypto_closeSession(
    SeosCryptoApi_Ptr api)
{
    seos_err_t err;

    if ((err = SeosCryptoApi_free(api)) != SEOS_SUCCESS)
    {
        Debug_LOG_TRACE("SeosCryptoApi_free failed with %d", err);
    }

    free(api);

    return err;
}

seos_err_t
KeyStore_getRpcHandle(SeosKeyStoreRpc_Handle* instance)
{
    static SeosKeyStore keyStore;
    static SeosKeyStoreRpc the_one;
    static KeyStoreContext keyStoreCtx;

    if (!keyStoreContext_ctor(&keyStoreCtx, 6, (void*)chanMuxDataPort))
    {
        Debug_LOG_ERROR("%s: Failed to initialize the test!", __func__);
        return 0;
    }

    seos_err_t retval = SeosKeyStore_init(&keyStore,
                                          keyStoreCtx.fileStreamFactory,
                                          cryptoInst,
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

static int dummyEntropyFunc(void* ctx, unsigned char* buf, size_t len)
{
    return 0;
}
