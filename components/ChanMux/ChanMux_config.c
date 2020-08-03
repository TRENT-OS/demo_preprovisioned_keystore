/*
 *  Channel MUX
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "system_config.h"
#include "ChanMux/ChanMux.h"
#include <camkes.h>


//------------------------------------------------------------------------------
static unsigned int
resolveChannel(
    unsigned int  sender_id,
    unsigned int  chanNum_local)
{
    return (CHANMUX_ID == sender_id) ? CHANMUX_CHANNEL_NVM : INVALID_CHANNEL;
}


//------------------------------------------------------------------------------
static uint8_t nvm_fifo[PAGE_SIZE];
static ChanMux_Channel_t nvm_channel;


//------------------------------------------------------------------------------
static const ChanMux_ChannelCtx_t channelCtx[] = {

    CHANMUX_CHANNEL_CTX(
        CHANMUX_CHANNEL_NVM,
        &nvm_channel,
        nvm_fifo, // must be the buffer and not a pointer
        CHANMUX_DATAPORT_ASSIGN(chanMuxStorage_chan_portRead,
                                chanMuxStorage_chan_portWrite),
        chanMuxStorage_chan_DataAvailable_emit),

};


//------------------------------------------------------------------------------
// this is used by the ChanMux component
const ChanMux_Config_t cfgChanMux =
{
    .resolveChannel = &resolveChannel,
    .numChannels    = ARRAY_SIZE(channelCtx),
    .channelCtx     = channelCtx,
};
