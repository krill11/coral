#!/bin/bash

# Create initrd directory if it doesn't exist
mkdir -p initrd

# Create basic directory structure
mkdir -p initrd/bin initrd/lib initrd/etc

# Copy system files
cp -r ../initrd/* initrd/

# Create initrd image
find initrd -print0 | cpio -o0 -H newc | gzip > initrd.img

# Copy initrd image to boot directory
cp initrd.img ../boot/initrd.img

echo "Initrd image created successfully!" 