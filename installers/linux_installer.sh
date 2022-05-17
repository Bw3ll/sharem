#!/bin/bash

sudo apt-get install vim git python3-pip make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl libffi-dev python3 python3-setuptools automake autoconf libtool -y

sudo BUILD_LIB=1 pip install ssdeep

python3 ../sharem/setup.py install
python3 -m pip install -e ../sharem 

exec $SHELL