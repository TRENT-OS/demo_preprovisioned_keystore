#!/bin/bash -em

#-------------------------------------------------------------------------------
#
# Script to run the IoT Demo
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
CURRENT_SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
DIR_BIN_SDK=${CURRENT_SCRIPT_DIR}/../../../bin

PROJECT_PATH=$1

if [ -z ${PROJECT_PATH} ]; then
    echo "ERROR: missing path to project build!"
    echo "Usage: ./run_demo.sh <path-to-project-build>"
    exit 1
fi

shift 1

IMAGE_PATH=${PROJECT_PATH}/images/capdl-loader-image-arm-zynq7000

echo "Creating KeyStore provisioned partition"
# run the tool with the key file provided by the system. The created
# image needs to be named "nvm_06", since the system makes use of the Proxy App
# which expects the NVM file name to follow the naming convention
# "nvm_[channelID]". The system makes use of the first NVM channel of the Proxy,
# which maps to the channel number six of the App -> nvm_06.
python3 \
    -B \
    ${DIR_BIN_SDK}/xmlParser.py \
    ${CURRENT_SCRIPT_DIR}/preprovisionedKeys.xml \
    ${DIR_BIN_SDK}/kpt
sleep 1

QEMU_PARAMS=(
    -machine xilinx-zynq-a9
    -m size=512M
    -nographic
    -s
    -serial tcp:localhost:4444,server
    -serial mon:stdio
    -kernel ${IMAGE_PATH}
)

# run QEMU
qemu-system-arm  ${QEMU_PARAMS[@]} $@ 2> qemu_stderr.txt &
sleep 1

# start proxy app
${DIR_BIN_SDK}/proxy_app -c TCP:4444 -t 1  > proxy_app.out &
sleep 1

fg
