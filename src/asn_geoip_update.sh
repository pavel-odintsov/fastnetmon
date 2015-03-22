#!/usr/bin/env bash

# Current dir
pushd "$(dirname $0)" >/dev/null
SCRIPT_DIR="$(pwd -P)"
popd >/dev/null

OS_TYPE=$(uname)

echo "Getting GeoIPASNum.dat GeoIPASNumv6.dat..."

# ASN (+IPv6) Database
if [ "$OS_TYPE" = "Linux" ];then
    wget -qO - "http://geolite.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz" | gunzip -cv > "${SCRIPT_DIR}/GeoIPASNum.dat"
    wget -qO - "http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz" | gunzip -cv > "${SCRIPT_DIR}/GeoIPASNumv6.dat"
elif [ "$OS_TYPE" = "Darwin" ];then
    curl -sq "http://geolite.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz" | gunzip -v -c > "${SCRIPT_DIR}/GeoIPASNum.dat"
    curl -sq "http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz" | gunzip -v -c > "${SCRIPT_DIR}/GeoIPASNumv6.dat"
elif [ "$OS_TYPE" = "FreeBSD" ];then
    fetch -qo - "http://geolite.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz" | gunzip -cv > "${SCRIPT_DIR}/GeoIPASNum.dat"
    fetch -qo - "http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz" | gunzip -cv > "${SCRIPT_DIR}/GeoIPASNumv6.dat"
fi

echo "Done."
