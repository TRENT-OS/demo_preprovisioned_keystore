#
# Test Preprovisioned Keystore
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(system_config.h)

project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})

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
        system_config
        os_core_api
        os_libs
        os_filesystem
        os_crypto
        os_keystore
)

# Use the existing entropy source, which at this point is just some dummy
DeclareCAmkESComponent_EntropySource(
    EntropySource
)

DeclareCAmkESComponent_ChanMux_Storage(
    ChanMux_Storage
)

DeclareCAmkESComponent_ChanMux(
    ChanMux
    components/ChanMux/ChanMux_config.c
    system_config
)

DeclareCAmkESComponent_UART(
    UART
)

#ROOT SERVER
DeclareAndCreateCamkESSystem(DemoAppTopLevel.camkes)
GenerateSimulateScript()
