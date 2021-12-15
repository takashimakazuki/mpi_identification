#!/bin/bash

curDir=$(cd $(dirname $0);pwd) 
sudo docker run -v $curDir:/app --privileged --rm -t -e container=docker doca_v1.11_bluefield_os_ubuntu_20.04-mlnx-5.4  /app/src/build_app.sh

scp $curDir/src/build/log_mpi bluefield:/tmp
