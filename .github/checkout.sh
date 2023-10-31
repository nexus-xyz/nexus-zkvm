#!/bin/sh

set -e
eval `ssh-agent -s`
echo $deploy_key | ssh-add -
echo
cargo update
