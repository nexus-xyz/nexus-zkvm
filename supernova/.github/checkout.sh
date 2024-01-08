#!/bin/sh

set -e
eval `ssh-agent -s`
echo "$deploy_key" > key
chmod 600 key
ssh-add key
echo
cargo update