cd /t

pip3 install wheel
pip3 install .

rm -rf ${DEPOT_TOOLS_PATH} 2> /dev/null
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git ${DEPOT_TOOLS_PATH}

rm -rf ${TEMP_ENGINE} 2> /dev/null
git clone https://github.com/flutter/flutter.git ${TEMP_ENGINE}

rm -rf ${ENGINE_PATH} 2> /dev/null
mkdir -p ${ENGINE_PATH}
cd ${TEMP_ENGINE}

git config --global user.email \"reflutter@example.com\"
git config --global user.name \"reflutter\"
git fetch origin ${COMMIT}
git reset --hard FETCH_HEAD

reflutter -b ${HASH_PATCH} -p

echo 'reflutter' > REFLUTTER
git add .
git commit -am \"reflutter\"

cd ${ENGINE_PATH}
echo 'solutions = [{\"managed\": False,\"name\": \"engine/src/flutter\",\"url\": \"'${TEMP_ENGINE}'\",\"custom_deps\": {},\"deps_file\": \"DEPS\",\"safesync_url\": \"\",},]' > .gclient
gclient sync

reflutter -b ${HASH_PATCH} -p

echo \"Wait... Change the source code...\"
sleep $WAIT

if [ \"$arm64\" != \"0\" ]; then src/flutter/tools/gn --no-goma --android --android-cpu=arm64 --runtime-mode=release
ninja -C src/out/android_release_arm64
cp src/out/android_release_arm64/lib.stripped/libflutter.so /libflutter_arm64.so ;fi

if [ \"$arm\" != \"0\" ]; then src/flutter/tools/gn --no-goma --android --android-cpu=arm --runtime-mode=release
ninja -C src/out/android_release
cp src/out/android_release/lib.stripped/libflutter.so /libflutter_arm.so ;fi

if [ \"$x64\" != \"0\" ]; then src/flutter/tools/gn --no-goma --android --android-cpu=x64 --runtime-mode=release
ninja -C src/out/android_release_x64
cp src/out/android_release_x64/lib.stripped/libflutter.so /libflutter_x64.so; fi

cd ..

cp -va *.so /t/
