#!/bin/bash
#
# netsimul project regenerated.

USERNAME=ga
VERSION=0.3

# enter target directory
cd /home/${USERNAME}/Downloads/

# copy tar file 
sudo cp /media/sf_public/project/netsimul-${VERSION}.tar .

# extract from tar and build
rm -rf netsimul/
tar -xvf netsimul-${VERSION}.tar
cd netsimul/src/build/
rm CMakeCache.txt
cmake .. && cmake .. && make

# enter directory back
cd -

