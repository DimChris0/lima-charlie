# Copyright 2015 refractionPOINT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import sys
import glob
import shutil
import platform

ret = 0

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )

parser = argparse.ArgumentParser()
parser.add_argument( '-v', '--version',
                     type = str,
                     required = True,
                     dest = 'version',
                     help = 'version string for the sensors' )

parser.add_argument( '-o', '--output',
                     type = str,
                     required = False,
                     dest = 'output',
                     default = os.path.join( root, 'prebuilt_binaries' ),
                     help = 'directory where release is written' )

args = parser.parse_args()

mainBinaries = [
    ( 'sensor/bin/macosx/*/x86_64/debug/rpHostCommonPlatformExe', 'hcp_osx_x64_debug_%s' ),
    ( 'sensor/bin/macosx/*/x86_64/release/rpHostCommonPlatformExe', 'hcp_osx_x64_release_%s' ),
    ( 'sensor/bin/debian/*/x86_64/debug/rpHostCommonPlatformExe', 'hcp_linux_x64_debug_%s' ),
    ( 'sensor/bin/debian/*/x86_64/release/rpHostCommonPlatformExe', 'hcp_linux_x64_release_%s' ),
    ( 'sensor/bin/ubuntu/*/x86_64/debug/rpHostCommonPlatformExe', 'hcp_linux_x64_debug_%s' ),
    ( 'sensor/bin/ubuntu/*/x86_64/release/rpHostCommonPlatformExe', 'hcp_linux_x64_release_%s' ),
    ( 'sensor/bin/centos/*/x86_64/debug/rpHostCommonPlatformExe', 'hcp_linux_x64_debug_%s' ),
    ( 'sensor/bin/centos/*/x86_64/release/rpHostCommonPlatformExe', 'hcp_linux_x64_release_%s' ),
    ( 'sensor/bin/windows/Win32/Debug/rphcp.exe', 'hcp_win_x86_debug_%s.exe' ),
    ( 'sensor/bin/windows/Win32/Release/rphcp.exe', 'hcp_win_x86_release_%s.exe' ),
    ( 'sensor/bin/windows/x64/Debug/rphcp.exe', 'hcp_win_x64_debug_%s.exe' ),
    ( 'sensor/bin/windows/x64/Release/rphcp.exe', 'hcp_win_x64_release_%s.exe' ),
    ( 'sensor/bin/macosx/*/x86_64/debug/librpHCP_HostBasedSensor.dylib', 'hbs_osx_x64_debug_%s.dylib' ),
    ( 'sensor/bin/macosx/*/x86_64/release/librpHCP_HostBasedSensor.dylib', 'hbs_osx_x64_release_%s.dylib' ),
    ( 'sensor/bin/debian/*/x86_64/debug/librpHCP_HostBasedSensor.so', 'hbs_linux_x64_debug_%s.so' ),
    ( 'sensor/bin/debian/*/x86_64/release/librpHCP_HostBasedSensor.so', 'hbs_linux_x64_release_%s.so' ),
    ( 'sensor/bin/ubuntu/*/x86_64/debug/librpHCP_HostBasedSensor.so', 'hbs_linux_x64_debug_%s.so' ),
    ( 'sensor/bin/ubuntu/*/x86_64/release/librpHCP_HostBasedSensor.so', 'hbs_linux_x64_release_%s.so' ),
    ( 'sensor/bin/centos/*/x86_64/debug/librpHCP_HostBasedSensor.so', 'hbs_linux_x64_debug_%s.so' ),
    ( 'sensor/bin/centos/*/x86_64/release/librpHCP_HostBasedSensor.so', 'hbs_linux_x64_release_%s.so' ),
    ( 'sensor/bin/windows/Win32/Debug/rpHCP_HostBasedSensor.dll', 'hbs_win_x86_debug_%s.dll' ),
    ( 'sensor/bin/windows/Win32/Release/rpHCP_HostBasedSensor.dll', 'hbs_win_x86_release_%s.dll' ),
    ( 'sensor/bin/windows/x64/Debug/rpHCP_HostBasedSensor.dll', 'hbs_win_x64_debug_%s.dll' ),
    ( 'sensor/bin/windows/x64/Release/rpHCP_HostBasedSensor.dll', 'hbs_win_x64_release_%s.dll' ),

    # Kernel Extension Modules
    ( 'sensor/bin/macosx/*/x86_64/debug/librpHCP_KernelAcquisition.dylib', 'kernel_osx_x64_debug_%s.dylib' ),
    ( 'sensor/bin/macosx/*/x86_64/release/librpHCP_KernelAcquisition.dylib', 'kernel_osx_x64_release_%s.dylib' ),
    ( 'sensor/bin/windows/x64/Release/rpHCP_KernelAcquisition.dll', 'kernel_win_x64_debug_%s.dll' ),
    ( 'sensor/bin/windows/x64/Debug/rpHCP_KernelAcquisition.dll', 'kernel_win_x64_release_%s.dll' ),
    ( 'sensor/bin/windows/Win32/Release/rpHCP_KernelAcquisition.dll', 'kernel_win_x86_debug_%s.dll' ),
    ( 'sensor/bin/windows/Win32/Debug/rpHCP_KernelAcquisition.dll', 'kernel_win_x86_release_%s.dll' ),
]

for sources, destination in mainBinaries:
    for file in glob.glob( os.path.join( root, sources ) ):
        dest = os.path.join( args.output, destination % ( args.version, ) )
        print( "Copying %s -> %s" % ( file, dest ) )
        try:
            shutil.copyfile( file, dest )
        except:
            e = sys.exc_info()[0]
            print( "ERROR: %s" % e )
            ret = 1
        if 'Darwin' in platform.platform() and '_osx_' in dest and 'hcp_' in dest:
            if 0 != os.system( 'codesign -s 24169A36E0B4AFFF9ACA33366FFE27546141468A %s' % dest ):
                print( "ERROR" )
                ret = 1


kernelModules = [
    ( 'sensor/sample_configs/sample_kernel_osx.conf', 'kernel_osx_x64_debug_%s.dylib' ),
    ( 'sensor/sample_configs/sample_kernel_osx.conf', 'kernel_osx_x64_release_%s.dylib' ),
    ( 'sensor/sample_configs/sample_kernel_win64.conf', 'kernel_win_x64_debug_%s.dll' ),
    ( 'sensor/sample_configs/sample_kernel_win64.conf', 'kernel_win_x64_release_%s.dll' ),
    ( 'sensor/sample_configs/sample_kernel_win32.conf', 'kernel_win_x86_debug_%s.dll' ),
    ( 'sensor/sample_configs/sample_kernel_win32.conf', 'kernel_win_x86_release_%s.dll' ),
]

for config, files in kernelModules:
    for file in glob.glob( os.path.join( args.output, files % args.version ) ):
        conf = os.path.join( root, config )
        print( "Setting config %s -> %s" % ( conf, file ) )
        if 0 != os.system( 'python %s %s %s' % ( os.path.join( root, 'sensor/scripts/set_sensor_config.py' ), conf, file ) ):
            print( "ERROR" )
            ret = 1

sys.exit( ret )
