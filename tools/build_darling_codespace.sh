#!/bin/bash
# Compila las partes de Linux de Darling (mldr y darlingserver) en un GitHub Codespace.
# Probado en un codespace "standardLinux32gb" (4 núcleos, 16 GB, Ubuntu 24.04) con Darling 60ba801d.
#
#   gh codespace create -R <usuario>/<repo> -m standardLinux32gb --idle-timeout 30m --retention-period 24h
#   gh codespace ssh -c <nombre> -- 'bash -s' < tools/build_darling_codespace.sh
#
# Notas aprendidas:
#  * Compilar en /tmp: está en un disco aparte (~118 GB). /workspaces solo tiene ~12 GB libres.
#  * git-lfs está instalado en el codespace y el submódulo src/external/swift intenta bajar bibliotecas
#    precompiladas de un servidor que pide credenciales. GIT_LFS_SKIP_SMUDGE=1 lo evita.
#  * Si el clon se aborta a mitad, los submódulos quedan con el commit correcto pero SIN archivos
#    (solo el fichero .git). "git submodule status" no lo delata: hay que forzar un reset en cada uno.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive GIT_LFS_SKIP_SMUDGE=1

sudo apt-get update -qq
sudo apt-get install -y -qq cmake clang bison flex libfuse-dev libudev-dev pkg-config libc6-dev-i386 \
  gcc-multilib libcairo2-dev libgl1-mesa-dev libtiff-dev libfreetype6-dev libelf-dev libxml2-dev \
  libegl1-mesa-dev libglu1-mesa-dev libfontconfig1-dev libbsd-dev ninja-build libxrandr-dev \
  libxcursor-dev libgif-dev libavcodec-dev libavformat-dev libswresample-dev libavutil-dev \
  libpulse-dev libdbus-1-dev libxkbfile-dev libcap-dev llvm-dev libvulkan-dev libcap2-bin python3 lld

cd /tmp
[ -d darling ] || git clone --depth 1 --recurse-submodules --shallow-submodules -j4 https://github.com/darlinghq/darling.git darling || true
cd darling
git submodule update --init --recursive --depth 1 -j4
git submodule foreach --recursive --quiet 'git reset --hard -q HEAD'

mkdir -p build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DTARGET_i386=OFF -DENABLE_METAL=OFF \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
ninja -j4 mldr darlingserver
ls -la src/startup/mldr/mldr src/external/darlingserver/darlingserver
