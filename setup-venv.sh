#!/bin/bash

python -m virtualenv .venv
source ./.venv/bin/activate
cd ./cdk
pip install -r requirements-dev.txt