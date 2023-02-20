#!/bin/bash
set -e

# Downloads a release of ccc and puts all the stdump executables in the right
# places. This file is called by the CI workflow for putting out new releases.

version='v1.1'

pushd $(dirname -- "$0")
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_linux.zip"
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_mac.zip"
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_windows.zip"
mkdir linux_x86_64
mkdir mac_x86_64
mkdir win_x86_64
unzip -j "ccc_$(echo $version)_linux.zip" "ccc_$(echo $version)_linux/stdump" -d linux_x86_64
unzip -j "ccc_$(echo $version)_mac.zip" "ccc_$(echo $version)_mac/stdump" -d mac_x86_64
unzip -j "ccc_$(echo $version)_windows.zip" "ccc_$(echo $version)_windows/stdump.exe" -d win_x86_64
rm "ccc_$(echo $version)_linux.zip"
rm "ccc_$(echo $version)_mac.zip"
rm "ccc_$(echo $version)_windows.zip"
popd
