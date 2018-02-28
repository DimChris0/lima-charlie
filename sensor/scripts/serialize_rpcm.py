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
import argparse
import uuid
sys.path.append( os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), '..', '..', 'cloud', 'beach' ) )

from hcp.utils.rpcm import rpcm
from hcp.utils.rpcm import rSequence
from hcp.utils.rpcm import rList
from hcp.Symbols import Symbols
from hcp.utils.hcp_helpers import AgentId
from hcp.utils.hcp_helpers import HcpOperations
from hcp.utils.hcp_helpers import HcpModuleId
from hcp.utils.hcp_helpers import HbsCollectorId
from hcp.utils.hcp_helpers import MemoryAccess
from hcp.utils.hcp_helpers import MemoryType

parser = argparse.ArgumentParser()
parser.add_argument( 'input',
                     type = argparse.FileType( 'rb' ),
                     help = 'file with the DSL representation of rpcm' )
parser.add_argument( 'output',
                     type = argparse.FileType( 'wb' ),
                     help = 'file where to output the serialized rpcm' )
args = parser.parse_args()

r = rpcm( isDebug = True )
rpcm_environment = { '_' : Symbols(), 'rList' : rList, 'rSequence' : rSequence, 'AgentId' : AgentId, 
                     'uuid' : uuid, 'HcpOperations' : HcpOperations, 'HcpModuleId' : HcpModuleId,
                     'HbsCollectorId' : HbsCollectorId, 'MemoryAccess' : MemoryAccess, 'MemoryType' : MemoryType }

conf = eval( args.input.read().replace( '\n', '' ), rpcm_environment )

serialized = conf.serialise()

args.output.write( serialized )
