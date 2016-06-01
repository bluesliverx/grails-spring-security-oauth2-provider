#!/bin/bash

set -e

GRAILS_3_0_X="3.0.17"
GRAILS_3_1_X="3.1.7"

GRAILS_SDKS_DIR="$HOME/sdk/grails/"

mkdir -p "$GRAILS_SDKS_DIR"

wget -P "$GRAILS_SDKS_DIR" "https://github.com/grails/grails-core/releases/download/v${GRAILS_3_0_X}/grails-${GRAILS_3_0_X}.zip"
wget -P "$GRAILS_SDKS_DIR" "https://github.com/grails/grails-core/releases/download/v${GRAILS_3_1_X}/grails-${GRAILS_3_1_X}.zip"

cd "$GRAILS_SDKS_DIR"

ln -s "grails-${GRAILS_3_0_X}" "$GRAILS_3_0_X"
ln -s "grails-${GRAILS_3_1_X}" "$GRAILS_3_1_X"

