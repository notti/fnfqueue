#!/bin/sh

docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW -v `pwd`:/io -t fnfqueue:current /io/test/run_tests_image.sh
