FROM ubuntu:22.04

ARG HASH_PATCH
ARG COMMIT
ARG arm
ARG arm64
ARG x64

ENV DEPOT_TOOLS_PATH=/depot_tools
ENV TEMP_ENGINE=/engine
ENV ENGINE_PATH=/customEngine
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/depot_tools
ENV WAIT=4
ENV arm64=${arm64:-arm64-v8a}
ENV arm=${arm:-armeabi-v7a}
ENV x64=${x64:-x86_64}
ENV HASH_PATCH=$HASH_PATCH
ENV COMMIT=$COMMIT

# Suppress git version warning
ENV GCLIENT_SUPPRESS_GIT_VERSION_WARNING=1

RUN apt-get update && \
  DEBIAN_FRONTEND="noninteractive" apt-get install -y \
  git git-svn git-man wget curl software-properties-common unzip \
  python3-pip python3 lsb-release sudo apt-transport-https tzdata \
  python3-pkgconfig default-jre default-jdk ninja-build && \
  mkdir t

ENTRYPOINT ["/bin/sh", "-c", "\
set -e && \
echo '=== Installing reFlutter ===' && \
cd /t && \
pip3 install wheel && \
pip3 install . && \
echo '=== Setting up depot_tools ===' && \
rm -rf ${DEPOT_TOOLS_PATH} 2> /dev/null && \
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git ${DEPOT_TOOLS_PATH} && \
echo '=== Cloning Flutter engine template ===' && \
rm -rf ${TEMP_ENGINE} 2> /dev/null && \
git clone https://github.com/flutter/engine.git ${TEMP_ENGINE} && \
cd ${TEMP_ENGINE} && \
git config --global user.email 'reflutter@example.com' && \
git config --global user.name 'reflutter' && \
echo '=== Checking out specific commit ===' && \
git fetch origin ${COMMIT} && \
git checkout ${COMMIT} && \
echo '=== Applying reFlutter patches ===' && \
reflutter -b ${HASH_PATCH} -p && \
echo 'reflutter' > REFLUTTER && \
git add . && \
git commit -am 'reflutter' || true && \
echo '=== Setting up engine workspace ===' && \
rm -rf ${ENGINE_PATH} 2> /dev/null && \
mkdir -p ${ENGINE_PATH}/src && \
cd ${ENGINE_PATH} && \
echo 'solutions = [{\"managed\": False,\"name\": \"src/flutter\",\"url\": \"'${TEMP_ENGINE}'\",\"custom_deps\": {},\"deps_file\": \"DEPS\",\"safesync_url\": \"\",},]' > .gclient && \
echo '=== Running gclient sync ===' && \
gclient sync -D --no-history || true && \
echo '=== Applying patches to synced source ===' && \
cd src/flutter && \
reflutter -b ${HASH_PATCH} -p || true && \
cd ${ENGINE_PATH} && \
echo '=== Waiting for manual modifications ($WAIT seconds) ===' && \
sleep \$WAIT && \
export NINJA_SUMMARIZE_BUILD=1 && \
if [ \"\$arm64\" != \"0\" ]; then \
  echo '=== Building ARM64 ===' && \
  src/flutter/tools/gn --no-goma --android --android-cpu=arm64 --runtime-mode=release && \
  ninja -C src/out/android_release_arm64 && \
  cp src/out/android_release_arm64/lib.stripped/libflutter.so /libflutter_arm64.so && \
  echo '✓ ARM64 build complete'; \
fi && \
if [ \"\$arm\" != \"0\" ]; then \
  echo '=== Building ARM ===' && \
  src/flutter/tools/gn --no-goma --android --android-cpu=arm --runtime-mode=release && \
  ninja -C src/out/android_release && \
  cp src/out/android_release/lib.stripped/libflutter.so /libflutter_arm.so && \
  echo '✓ ARM build complete'; \
fi && \
if [ \"\$x64\" != \"0\" ]; then \
  echo '=== Building x64 ===' && \
  src/flutter/tools/gn --no-goma --android --android-cpu=x64 --runtime-mode=release && \
  ninja -C src/out/android_release_x64 && \
  cp src/out/android_release_x64/lib.stripped/libflutter.so /libflutter_x64.so && \
  echo '✓ x64 build complete'; \
fi && \
cd / && \
cp -va *.so /t/ && \
echo '=== Build artifacts copied to /t/ ===' && \
ls -lh /t/*.so || echo 'No .so files found'"]

CMD ["bash"]
