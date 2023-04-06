#!/bin/sh
apt install libpcsclite-dev -y
cp -f libkalkancryptwr-64.so libkalkancryptwr-64.so.1.1.1 /lib/x86_64-linux-gnu/
chmod -x /lib/x86_64-linux-gnu/libkalkancryptwr-64.so.1.1.1

cp -rf ../libs_for_linux/kalkancrypt /opt/
rm /opt/kalkancrypt/libxml2.so.2
#ln -s /opt/kalkancrypt/libxml2.so.2 /opt/kalkancrypt/libxml2.so.2.9.4
rm /opt/kalkancrypt/libxmlsec1-openssl.so.1
ln -s /opt/kalkancrypt/libxmlsec1-openssl.so.1 /opt/kalkancrypt/libxmlsec1-openssl.so.1.2.24
rm /opt/kalkancrypt/libxmlsec1.so.1
ln -s /opt/kalkancrypt/libxmlsec1.so.1 /opt/kalkancrypt/libxmlsec1.so.1.2.2
rm /opt/kalkancrypt/libxslt.so.1
ln -s libxslt.so.1 libxslt.so.1.1.29

cp ld.kalkan.conf /etc/ld.so.conf.d/
ldconfig
