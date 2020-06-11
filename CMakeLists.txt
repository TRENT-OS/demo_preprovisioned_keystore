#
# Test Preprovisioned Keystore
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(config.h)

os_use_libs(
    OS_LIBS
    OS_CRYPTO
    OS_CHANMUX
    OS_KEYSTORE
    OS_FILESYSTEM_SPIFFS_LEGACY
)

# this is used by the keystore to decide which files are built into the lib. It
# works because this is not simply a variable, but a configuration variable
# that is preserved after it got defined. The current build process runs the
# cmake config multiple times. This is set in the first run after the keystore
# config was done, so in the 2nd cmake config run the new keystore config is
# used then. A cleaner that does not require multiple config runs is having
# multiple keystore libs, the the component here as to pick what is needed. Or
# even make them interface libs that contribute C-file here.
set(KEYSTORE_AS_COMPONENT ON CACHE BOOL "" FORCE)


#-------------------------------------------------------------------------------
project(tests_keystore_demo C)

DeclareCAmkESComponent(
    DemoApp
    INCLUDES
        common
    SOURCES
        components/DemoApp/src/demoApp.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        os_libs
        os_filesystem_spiffs_legacy
        os_crypto
        proxy_nvm
        chanmux_client
        os_keystore
)

DeclareCAmkESComponent(
    UartDrv
    SOURCES
        components/Uart/src/UartDrv.c
        components/Uart/src/qemu_uart.c
    C_FLAGS
        -Wall
        -Werror
)

DeclareCAmkESComponent(
    ChanMux
    SOURCES
        components/ChanMux/src/instance/ChanMux_Instance.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        chanmux_server
)

DeclareAndCreateCamkESSystem(DemoAppTopLevel.camkes)
GenerateSimulateScript()
