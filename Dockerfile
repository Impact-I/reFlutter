FROM ubuntu:18.04

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

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y git git-svn git-man wget curl software-properties-common unzip python3-pip python3 lsb-release sudo apt-transport-https tzdata && \
    mkdir t

ENTRYPOINT ["/bin/sh", "-c", "cd /t && pip3 install wheel && pip3 install . && rm -rf ${DEPOT_TOOLS_PATH} 2> /dev/null && git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git $DEPOT_TOOLS_PATH && rm -rf ${TEMP_ENGINE} 2> /dev/null && git clone https://github.com/flutter/engine.git $TEMP_ENGINE && rm -rf ${ENGINE_PATH} 2> /dev/null && mkdir --parents $ENGINE_PATH && cd $TEMP_ENGINE && git config --global user.email \"reflutter@example.com\" && git config --global user.name \"reflutter\" && git fetch origin $COMMIT && git reset --hard FETCH_HEAD && reflutter $HASH_PATCH -l && echo 'reflutter' > REFLUTTER && git add . && git commit -am \"reflutter\" && cd $ENGINE_PATH && echo 'solutions = [{\"managed\": False,\"name\": \"src/flutter\",\"url\": \"'$TEMP_ENGINE'\",\"custom_deps\": {},\"deps_file\": \"DEPS\",\"safesync_url\": \"\",},]' > .gclient && gclient sync && reflutter $HASH_PATCH -l && echo \"Wait... Change the source code...\" && sleep $WAIT && src/build/install-build-deps-android.sh --no-prompt && if [ \"$arm64\" != \"0\" ]; then src/flutter/tools/gn --no-goma --android --android-cpu=arm64 --runtime-mode=release && ninja -C src/out/android_release_arm64 && cp src/out/android_release_arm64/lib.stripped/libflutter.so /libflutter_arm64.so ;fi && if [ \"$arm\" != \"0\" ]; then src/flutter/tools/gn --no-goma --android --android-cpu=arm --runtime-mode=release && ninja -C src/out/android_release && cp src/out/android_release/lib.stripped/libflutter.so /libflutter_arm.so ;fi && if [ \"$x64\" != \"0\" ]; then src/flutter/tools/gn --no-goma --android --android-cpu=x64 --runtime-mode=release && ninja -C src/out/android_release_x64 && cp src/out/android_release_x64/lib.stripped/libflutter.so /libflutter_x64.so; fi &&  cd .. && cp -va *.so /t/"]


CMD ["bash"]
