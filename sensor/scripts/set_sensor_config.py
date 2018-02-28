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
sys.path.append( os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), '..', '..', 'cloud', 'beach' ) )
os.chdir( os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), '..', '..' ) )

from hcp.utils.rpcm import rpcm
from hcp.utils.rpcm import rSequence
from hcp.utils.rpcm import rList
from hcp.Symbols import Symbols
from hcp.utils.hcp_helpers import AgentId

import sys
import tarfile
import uuid
import tempfile

# This is the key also defined in the sensor as _HCP_DEFAULT_STATIC_STORE_KEY
# and used with the same algorithm as obfuscationLib
OBFUSCATION_KEY = "\xFA\x75\x01"
STATIC_STORE_MAX_SIZE = 1024 * 50

def obfuscate( buffer, key ):
    obf = ''
    index = 0
    for hx in buffer:
        obf = obf + chr( ( ( ord( key[ index % len( key ) ] ) ^ ( index % 255 ) ) ^ ( STATIC_STORE_MAX_SIZE % 255 ) ) ^ ord( hx ) )
        index = index + 1
    return obf


def tarGzOf( filePath, archiveName, payloadName ):
    tmpDir = tempfile.mkdtemp()
    os.system( 'rm -rf %s/%s' % ( tmpDir, payloadName, ) )
    os.system( 'cp -R %s %s/%s' % ( filePath, tmpDir, payloadName ) )
    tar = tarfile.open( '%s/%s' % ( tmpDir, archiveName, ), 'w:gz' )
    tar.add( '%s/%s' % ( tmpDir, payloadName ), arcname = payloadName )
    tar.close()
    with open( '%s/%s' % ( tmpDir, archiveName, ), 'rb' ) as f:
        val = f.read()
    os.unlink( '%s/%s' % ( tmpDir, archiveName, ) )
    return val

if 3 > len( sys.argv ):
    print( "Usage: set_sensor_config.py configFile sensorExec [installer-uuid]" )
    sys.exit( -1 )

configFile = open( sys.argv[ 1 ], 'rb' ).read()
sensorFile = open( sys.argv[ 2 ], 'rb' )
installerUuid = uuid.UUID( sys.argv[ 3 ] ) if len( sys.argv ) >= 4 else uuid.UUID( '00000000-0000-0000-0000-000000000001' )
sensor = sensorFile.read()
sensorFile.close()

prevPath = os.getcwd()
os.chdir( os.path.join( os.path.dirname( __file__ ), '..', '..' ) )

r = rpcm( isDebug = True )
rpcm_environment = { '_' : Symbols(), 'rList' : rList, 'rSequence' : rSequence, 'AgentId' : AgentId, 'tarGzOf' : tarGzOf, 'INSTALLER_UUID' : installerUuid, 'uuid' : uuid }

conf = eval( configFile.replace( '\n', '' ), rpcm_environment )

conf = obfuscate( r.serialise( conf ), OBFUSCATION_KEY )

magic = "\xFA\x57\xF0\x0D" + ( "\x00" * ( len( conf ) - 4 ) )

os.chdir( prevPath )

if magic in sensor:
    sensor = sensor.replace( magic, conf )
    sensorFile = open( sys.argv[ 2 ], 'wb' )
    sensorFile.write( sensor )
    sensorFile.close()
    print( "Sensor patched." )
else:
    print( "Sensor ALREADY PATCHED." )
    sys.exit( -1 )

