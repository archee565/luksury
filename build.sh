#!/bin/bash
mkdir -p build
rm -f build/*
cd build
g++ -c ../luksury.cpp ../remover.cpp -Wno-write-strings -Wno-ignored-attributes
gcc -c ../pcr-oracle/*.c -I ../pcr-oracle -I/usr/include/tss2  -I/usr/include/libfdisk -I/usr/include/uuid -I/usr/include/blkid
cd ..
g++ -o luksury build/*.o -ltss2-esys -ltss2-tctildr -ltss2-rc -ltss2-mu -lcrypto -ljson-c -lfdisk -lelf -ljsoncpp
