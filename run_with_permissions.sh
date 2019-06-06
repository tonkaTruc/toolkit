#!/bin/bash

sudo su
source venv/bin/activate
echo "Permissions and source environment have been set."

python3 packet_toolkit.py

