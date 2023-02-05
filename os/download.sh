#!/bin/bash
set -e
# Downloads a release of ccc and puts all the stdump executables in the right
# places. This file is called by the CI workflow for putting out new releases.

pushd $(dirname -- "$0")
wget https://github.com/chaoticgd/ccc/releases/download/v1.0/ccc_v1.0_linux.zip
wget https://github.com/chaoticgd/ccc/releases/download/v1.0/ccc_v1.0_mac.zip
wget https://github.com/chaoticgd/ccc/releases/download/v1.0/ccc_v1.0_windows.zip
mkdir linux_x86_64
mkdir mac_x86_64
mkdir win_x86_64
unzip -j ccc_v1.0_linux.zip ccc_v1.0_linux/stdump -d linux_x86_64
unzip -j ccc_v1.0_mac.zip ccc_v1.0_mac/stdump -d mac_x86_64
unzip -j ccc_v1.0_windows.zip ccc_v1.0_windows/stdump.exe -d win_x86_64
rm ccc_v1.0_linux.zip
rm ccc_v1.0_mac.zip
rm ccc_v1.0_windows.zip
popd
