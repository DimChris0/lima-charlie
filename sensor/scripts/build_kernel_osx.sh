#! /bin/sh

rm -rf ./sensor/executables/hbs_kernel_acquisition/osx/build/Release/hbs_kernel_acquisition.kext
xcodebuild $1 -project ./sensor/executables/hbs_kernel_acquisition/osx/hbs_kernel_acquisition.xcodeproj/

mkdir -p ./sensor/bin/macosx/kernel
rm -rf ./sensor/bin/macosx/kernel/*
cp -R ./sensor/executables/hbs_kernel_acquisition/osx/build/Release/hbs_kernel_acquisition.kext ./sensor/bin/macosx/kernel/hbs_kernel_acquisition_64.kext

