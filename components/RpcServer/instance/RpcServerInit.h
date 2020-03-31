/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "ChanMuxNvmDriver.h"
#include "AesNvm.h"
#include "SeosSpiffs.h"
#include "SpiffsFileStream.h"
#include "SpiffsFileStreamFactory.h"
#include "SeosKeyStore.h"

typedef struct KeyStoreContext
{
    ChanMuxNvmDriver chanMuxNvm;
    OS_Crypto_Handle_t hCrypto;
    AesNvm aesNvm;
    SeosSpiffs fs;
    FileStreamFactory* fileStreamFactory;
    SeosKeyStore keyStore;
} KeyStoreContext;

bool keyStoreContext_ctor(KeyStoreContext*  keyStoreCtx,
                          uint8_t           channelNum,
                          void*             dataport);

bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx);
