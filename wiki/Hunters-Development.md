# Hunters Development

## Overview

Hunters are high level pieces of logic that you can write to bind together all the different systems and features available in LC together. It gives you execution in two different modes:

1. Recurring: execute the hunter on a timer every X seconds. This is most useful to execute complex and demanding logic on data in the cloud and telemetry collection on sensors that cannot be run constantly.
1. From detect: execute the hunter when a specific event is generated. This is most useful to automate the logic of investigation of detects.

The hunter itself has access to many data sources including:

1. The full corpus of previous detections.
1. Tasking one and any sensors directly.
1. The VirusTotal API.
1. The large-scale Model which includes:
  1. Full event stream from all sensors.
  1. All Objects recorded, pre-pivoted and their statistics.
  1. The current sensor statuses.
  1. A generic, persisted scalable Key Value store to be used for any purpose.

In addition to all this, Hunters executing in response to a detect also automatically get notified for every event coming back from the sensors that is related to the current investigation. The current investigation concept is implemented using a generic context structure passed to the hunter with every event received. A hunter may also manually register/unregister to any specific events or investigations.

## Structure

### Declaration & initialization

As usual of other actors, we import the super class, in this case `Hunt`, which our Hunter will inherit from, as well as any helper methods we need.

The contract of the `Hunt` class provides `init`, `deinit` and `updateHunt`. In addition to these functions, you can define a `detects` class variable (not instance), which should be a tuple of the detect types which your hunt is interested in. Finally, if you want your Hunter to run on a schedule, just use the `schedule` function in the `init`.

```
from beach.actor import Actor
import hashlib
Hunt = Actor.importLib( '../../Hunts', 'Hunt' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../../hcp_helpers', '_x_' )
exeFromPath = Actor.importLib( '../../hcp_helpers', 'exeFromPath' )

class SuspectedDropperHunt ( Hunt ):
    detects = ( 'WinSuspExecName', )

    def init( self, parameters ):
        super( SuspectedDropperHunt, self ).init( parameters )
```

### Main entry point

The main entry point of a Hunter is the `updateHunt` function, which receives a context and a newMessage. The context is provided and persisted for you between calls to updateHunt based on each investigation id (every instance of a detect). The context is simply a `dict` that you can update to keep contextual information during the investigation. The newMessage variable is set to `None` to indicate the call to `updateHunt` is the first call for a new detect, and it is set to a message related to the investigation for follow up events.

```
def updateHunt( self, context, newMsg ):
        if newMsg is None:
```

### Data access & tasking

Access to the different data models is done through `actorHandle`s which are provided for you. The example below shows accessing the generic Key Value feature of the data Model, getting the value of the key `fileHash` in the 'inv_files' category (the Key Value store uses categories for segmentation).

```
resp = self.Models.request( 'get_kv', { 'cat' : 'inv_files', 'k' : fileHash } )
```

The example below shows off the tasking feature, which is very similar to the tasking in the stateless actors. The first argument is the sensor id to send the task to, while the second if a list of commands where each command is a tuple of the command and its arguments as defined in the command line interface (admin_cli.py). The last two parameters are the expiry, indicating after how much time the sensor should disregard the tasking (for time-sensitive tasks), and the investigation id used to track the current investigation context.

```
self.task( source, ( ( 'mem_strings', pid ),
                     ( 'file_get', filePath ),
                     ( 'file_info', filePath ),
                     ( 'history_dump', ),
                     ( 'exfil_add', 'notification.FILE_CREATE', '--expire', 60 ),
                     ( 'exfil_add', 'notification.FILE_DELETE', '--expire', 60 ),
                     ( 'os_services', ),
                     ( 'os_drivers', ),
                     ( 'os_autoruns', ) ),
           expiry = 60,
           inv_id = inv_id )
```

### Context modification

Finally, as you process the investigation of a detect, or whatever type of Hunter you're doing, you can post an update to the detect by calling the `postUpdatedDetect` with the modified context. This will post the updated information to the database where the original detect is stored.

```
self.postUpdatedDetect( context )
```
