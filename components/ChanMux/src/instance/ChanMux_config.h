/*
 * WAN/LAN Channel MUX
 *
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    CHANNEL_LAN_DATA,       // 0
    CHANNEL_WAN_DATA,       // 1
    CHANNEL_LAN_CTRL,       // 2
    CHANNEL_WAN_CTRL,       // 3
    CHANNEL_NW_STACK_CTRL,  // 4
    CHANNEL_NW_STACK_DATA,  // 5
    CHANNEL_MAIN_DATA,      // 6

    CHANMUX_NUM_CHANNELS    // 7
};

#ifdef __cplusplus
}
#endif
