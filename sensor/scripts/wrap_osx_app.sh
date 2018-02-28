#! /bin/sh

APP_TO_WRAP="$1"
OUTPUT_FILE="$2.app"

cp -R ./sensor/scripts/limacharlie.app $OUTPUT_FILE
cp $APP_TO_WRAP $OUTPUT_FILE/Contents/MacOS/rphcp

