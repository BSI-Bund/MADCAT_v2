#!/bin/bash
function native {
  echo ====== native ======
  cmake -Bbuild
  cd build
  make
  cd ..
}

function armhf {
  echo ======  armhf =====
  cmake -DCMAKE_TARGET=armhf -Bbuild-armhf
  cd build-armhf
  make
  cd ..
}

function aarch64 {
  echo ===== aarch64 =====
  cmake -DCMAKE_TARGET=aarch64 -Bbuild-aarch64
  cd build-aarch64
  make
  cd ..
}

rm uninstall.sh
case $1 in
native)   native
          exit 0;;
armhf)    armhf
          exit 0;;
aarch64)  aarch64
          exit 0;;
all)      native
          armhf
          aarch64
          exit 0;;
*)        native
          exit 0;;
esac

