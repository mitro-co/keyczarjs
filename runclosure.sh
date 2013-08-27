#!/bin/sh

set -e

java -jar ~/Downloads/compiler.jar --language_in=ECMASCRIPT5_STRICT --warning_level VERBOSE \
  --jscomp_off missingProperties --externs externs_forge.js \
  --js keyczar.js keyczar_test.js keyczar_util.js keyczar_util_test.js roundtripper.js \
  test_util.js --js_output_file /dev/null
