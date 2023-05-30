ADD file:0d82cd095966e8ee78b593cb47a352eec842edb7bd9d9468e8a70154522447d1 in /
CMD ["bash"]
ENV DEPOT_TOOLS_PATH=/depot_tools
ENV TEMP_ENGINE=/engine
ENV ENGINE_PATH=/customEngine
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/depot_tools
ENV WAIT=4
ENV arm64=arm64-v8a
ENV arm=armeabi-v7a
ENV x64=x86_64
ENV HASH_PATCH=e4a09dbf2bb120fe4674e0576617a0dc
ENV COMMIT=a9d88a4d182bdae23e3a4989abfb7ea25954aad1
CMD /bin/sh -c apt-get update && apt-get install -y git wget curl software-properties-common unzip python-pip python lsb-release sudo apt-transport-https && DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata && mkdir t
ENTRYPOINT ["/bin/sh", "-c", "pip install reflutter &&     git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git $DEPOT_TOOLS_PATH &&     git clone https://github.com/flutter/engine.git &&     mkdir --parents $ENGINE_PATH &&     cd $TEMP_ENGINE &&     git config --global user.email \"reflutter@example.com\" && git config --global user.name \"reflutter\" &&     git fetch origin $COMMIT &&     git reset --hard FETCH_HEAD &&     reflutter $HASH_PATCH -l &&     echo 'reflutter' > REFLUTTER &&     git add . && git commit -am \"reflutter\" &&     cd $ENGINE_PATH &&     echo 'solutions = [{\"managed\": False,\"name\": \"src/flutter\",\"url\": \"'$TEMP_ENGINE'\",\"custom_deps\": {},\"deps_file\": \"DEPS\",\"safesync_url\": \"\",},]' > .gclient &&     gclient sync &&     reflutter $HASH_PATCH -l &&     echo \"Wait... Change the source code...\" && sleep $WAIT &&     src/build/install-build-deps-android.sh --no-prompt &&     if [ \"$arm64\" != \"0\" ]; then src/flutter/tools/gn --android --android-cpu=arm64 --runtime-mode=release && ninja -C src/out/android_release_arm64 && cp src/out/android_release_arm64/lib.stripped/libflutter.so /libflutter_arm64.so ;fi &&     if [ \"$arm\" != \"0\" ]; then src/flutter/tools/gn --android --android-cpu=arm --runtime-mode=release && ninja -C src/out/android_release && cp src/out/android_release/lib.stripped/libflutter.so /libflutter_arm.so ;fi &&     if [ \"$x64\" != \"0\" ]; then src/flutter/tools/gn --android --android-cpu=x64 --runtime-mode=release && ninja -C src/out/android_release_x64 && cp src/out/android_release_x64/lib.stripped/libflutter.so /libflutter_x64.so; fi &&  cd .. &&   cp -va *.so /t/"]