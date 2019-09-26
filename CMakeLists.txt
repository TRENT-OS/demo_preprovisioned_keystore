cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_KEYSTORE
    SPIFFS
)

project(tests_keystore_demo C)

DeclareCAmkESComponent(DemoApp
    INCLUDES
        common
    SOURCES
        components/DemoApp/src/demoApp.c
        components/DemoApp/src/initDemo.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
        seos_crypto
        seos_keystore
)

DeclareCAmkESComponent(CryptoServer
    INCLUDES
        common
    SOURCES
        components/CryptoServer/instance/CryptoServer.c
        components/CryptoServer/instance/CryptoServerInit.c
        ${SEOS_LIBS_DIR}/seos_crypto/src/SeosCryptoRpc.c
        ${SEOS_LIBS_DIR}/seos_keystore/src/SeosKeyStoreRpc.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
        seos_crypto
        seos_keystore
)

DeclareCAmkESComponent(UartDrv
    SOURCES
        components/Uart/src/UartDrv.c
        components/Uart/src/qemu_uart.c
    C_FLAGS
        -Wall -Werror
)

DeclareCAmkESComponent(ChanMux
    SOURCES
        components/ChanMux/src/instance/ChanMux_Instance.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
)

DeclareCAmkESRootserver(DemoAppTopLevel.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
