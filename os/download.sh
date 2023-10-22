#!/bin/bash
set -e

# Downloads a release of ccc and puts all the stdump executables in the right
# places. This file is called by the CI workflow for putting out new releases.

version='v1.2.1'

pushd $(dirname -- "$0")
rm -f "ccc_$(echo $version)_linux.zip"
rm -f "ccc_$(echo $version)_mac.zip"
rm -f "ccc_$(echo $version)_windows.zip"
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_linux.zip"
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_mac.zip"
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_windows.zip"
mkdir -p linux_x86_64
mkdir -p mac_x86_64
mkdir -p win_x86_64
unzip -j "ccc_$(echo $version)_linux.zip" "ccc_$(echo $version)_linux/stdump" -d linux_x86_64
unzip -j "ccc_$(echo $version)_mac.zip" "ccc_$(echo $version)_mac/stdump" -d mac_x86_64
unzip -j "ccc_$(echo $version)_windows.zip" "ccc_$(echo $version)_windows/stdump.exe" -d win_x86_64
rm -f "ccc_$(echo $version)_linux.zip"
rm -f "ccc_$(echo $version)_mac.zip"
rm -f "ccc_$(echo $version)_windows.zip"
popd
