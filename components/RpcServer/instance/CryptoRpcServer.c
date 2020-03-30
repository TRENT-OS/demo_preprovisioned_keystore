/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "OS_Crypto.h"

#include "CryptoRpcServer.h"

#include <camkes.h>

static OS_Crypto_Handle_t hCrypto;

static int entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    return 0;
}

OS_Crypto_Handle_t
OS_CryptoRpcServer_getCrypto(
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
    OS_Crypto_Config_t cfg =
    {
        .mode = OS_Crypto_Mode_RPC_SERVER_WITH_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free   = free,
        },
        .impl.lib.rng = {
            .entropy = entropyFunc,
        },
        .server.dataPort = rpcServerDataport
    };

    if ((err = OS_Crypto_init(&hCrypto, &cfg)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init failed with %d", err);
    }

    return err;
}

seos_err_t
CryptoRpcServer_closeSession(
    void)
{
    seos_err_t err;

    if ((err = OS_Crypto_free(hCrypto)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_free failed with %d", err);
    }

    return err;
}