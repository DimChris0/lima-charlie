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

import os
import sys
import hashlib

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )
if 5 != len( sys.argv ):
    print( "Usage: hcp_config_file hbs_config_file hcp_root_key output_dir" )
    sys.exit(-1)

def printStep( step, *ret ):
    msg = '''
===============
Step: %s
Return Values: %s
===============

''' % ( step, str( ret ) )
    print( msg )
    if any( ret ):
        print( 'Stopping execution since this step failed.' )
        sys.exit(-1)

hcp_config = os.path.abspath( sys.argv[ 1 ] )
hbs_config = os.path.abspath( sys.argv[ 2 ] )
hcp_root_key = os.path.abspath( sys.argv[ 3 ] )
output_dir = os.path.abspath( sys.argv[ 4 ] )

if not os.path.isdir( output_dir ):
    printStep( 'Creating output directory.', 
               os.system( 'mkdir -p %s' % output_dir ) )

printStep( 'Copying prebuilt binaries to output.', 
           os.system( 'cp %s/prebuilt_binaries/* %s/' % ( root, output_dir ) ) )



binaries = os.listdir( output_dir )
for binary in binaries:
    if binary.startswith( 'hcp_' ) and not binary.endswith( '.sig' ):
        binaryPath = os.path.join( output_dir, binary )
        printStep( 'Setting HCP config on %s with %s.' % ( binaryPath, hcp_config ),
                   os.system( 'python %s %s %s' % ( os.path.join( root, 'sensor', 'scripts', 'set_sensor_config.py' ),
                                                    hcp_config, 
                                                    binaryPath ) ) )

binaries = os.listdir( output_dir )
for binary in binaries:
    if binary.startswith( 'hbs_' ) and not binary.endswith( '.sig' ):
        binaryPath = os.path.join( output_dir, binary )
        printStep( 'Setting HBS config on %s with %s.' % ( binaryPath, hbs_config ),
                   os.system( 'python %s %s %s' % ( os.path.join( root, 'sensor', 'scripts', 'set_sensor_config.py' ),
                                                    hbs_config, 
                                                    binaryPath ) ) )

binaries = os.listdir( output_dir )
for binary in binaries:
    if ( binary.startswith( 'hbs_' ) or 
         binary.startswith( 'hcp_' ) or 
         binary.startswith( 'kernel_' ) ) and not binary.endswith( '.sig' ):
        binaryPath = os.path.join( output_dir, binary )
        printStep( 'Signing binary: %s' % binary,
                   os.system( 'python %s -k %s -f %s -o %s' % ( os.path.join( root, 'tools', 'signing.py' ),
                                                                os.path.join( root, 'keys', hcp_root_key ),
                                                                binaryPath,
                                                                binaryPath + '.sig' ) ) )
