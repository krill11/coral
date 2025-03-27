#!/bin/bash

# Create temporary directory
mkdir -p tmp
cd tmp

# Download bash
wget https://ftp.gnu.org/gnu/bash/bash-5.2.15.tar.gz
tar xf bash-5.2.15.tar.gz
cd bash-5.2.15

# Configure and build bash
./configure --prefix=/ --host=i386-pc-linux-gnu
make
make DESTDIR=../../initrd install

# Download readline
cd ..
wget https://ftp.gnu.org/gnu/readline/readline-8.2.tar.gz
tar xf readline-8.2.tar.gz
cd readline-8.2

# Configure and build readline
./configure --prefix=/ --host=i386-pc-linux-gnu
make
make DESTDIR=../../initrd install

# Clean up
cd ../..
rm -rf tmp

echo "Dependencies downloaded and installed successfully!" 