/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoApi.h"

#include "CryptoRpcServer.h"

#include <camkes.h>

static SeosCryptoApiH hCrypto;

static int entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    return 0;
}

SeosCryptoApiH
SeosCryptoRpc_Server_getSeosCryptoApi(
    void)
{
    // We have only a single instance
    return hCrypto;
}

seos_err_t
CryptoRpcServer_openSession(
    void)
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
            .entropy = entropyFunc,
        },
        .server.dataPort = rpcServerDataport
    };

    if ((err = SeosCryptoApi_init(&hCrypto, &cfg)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_init failed with %d", err);
    }

    return err;
}

seos_err_t
CryptoRpcServer_closeSession(
    void)
{
    seos_err_t err;

    if ((err = SeosCryptoApi_free(hCrypto)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_free failed with %d", err);
    }

    return err;
}