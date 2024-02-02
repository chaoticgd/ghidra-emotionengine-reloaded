#!/bin/bash
set -e

# Downloads a release of ccc and puts all the stdump executables in the right
# places. This file is called by the CI workflow for putting out new releases.

pushd $(dirname -- "$0")

version='v1.2.1'

cat > shasums.txt <<EOF
7fc40cb63d32ac7b363733d9dab586f10e0c44afd79a4dc3bbe93c32d1d1b61e  ccc_v1.2.1_linux.zip
ab7d71b4a5255196a42728d97332548c9fabd213c9959dfc1edba243aeab9328  ccc_v1.2.1_mac.zip
1824cf630c339918d4b5a5d8c331e20f2dc08511774cf0c878ae5b2037e8962f  ccc_v1.2.1_windows.zip
EOF

rm -f "ccc_$(echo $version)_linux.zip"
rm -f "ccc_$(echo $version)_mac.zip"
rm -f "ccc_$(echo $version)_windows.zip"

wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_linux.zip"
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_mac.zip"
wget "https://github.com/chaoticgd/ccc/releases/download/$(echo $version)/ccc_$(echo $version)_windows.zip"

shasum -a 256 --check shasums.txt

mkdir -p linux_x86_64
mkdir -p mac_x86_64
mkdir -p win_x86_64

unzip -j "ccc_$(echo $version)_linux.zip" "ccc_$(echo $version)_linux/stdump" -d linux_x86_64
unzip -j "ccc_$(echo $version)_mac.zip" "ccc_$(echo $version)_mac/stdump" -d mac_x86_64
unzip -j "ccc_$(echo $version)_windows.zip" "ccc_$(echo $version)_windows/stdump.exe" -d win_x86_64

rm -f "ccc_$(echo $version)_linux.zip"
rm -f "ccc_$(echo $version)_mac.zip"
rm -f "ccc_$(echo $version)_windows.zip"
rm shasums.txt

popd
