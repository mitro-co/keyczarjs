#!/bin/sh

set -e

for test in *_test.js; do
    echo $test
    node $test
done
