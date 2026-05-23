#!/bin/bash

# vaultwarden: wrapper of Bitwarden's bw

# PROTOTYPE

# get session
# run pretty
# if a new session is given, store in /data/bw/session

# REPORT BUGS HERE:


# =======================================

set -euo pipefail

BW_SESSION=$(cat /data/bw/session) \
bw --pretty $@


# Verbose

echo -e "\nBW_SESSION=$(cat /data/bw/session) bw --pretty $@"
