cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_KEYSTORE
    SEOS_FILESYSTEM_SPIFFS
)

# this is used by the keystore to decide which files are build into the lib. It
# works because this is not simply a variable, but a configuration variable
# that is preserved after it got defined. The current build process runs the
# cmake config multiple times. This is set in the first run after the keystore
# config was done, so in the 2nd cmake config run the new keystore config is
# used then. A cleaner that does not require multiple config runs is having
# multiple keystore libs, the the component here as to pick what is needed. Or
# even make them interface libs that contribute C-file here.
set(KEYSTORE_AS_COMPONENT ON CACHE BOOL "" FORCE)

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
        seos_filesystem_spiffs
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
        seos_filesystem_spiffs
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
