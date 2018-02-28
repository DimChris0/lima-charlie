# Stateless Detection Development

Stateless detection, by its nature attempts to detect suspicious behavior by looking at events from the sensors in a one-event-at-a-time fashion, no correlation (correlations are in Stateful detection).

Creating a new stateless detection is trivial. The basic structure of a stateless detection is a single file with a single class (both have the same name as per Beach standards) implementing a single function. The file should be stored in `/cloud/beach/hcp/analytics/stateless/` for clarity.

Let's look at an example, `WinSuspExecName.py`, as a play-by-play:

## The imports

First we import the Actor dependency for Beach to allow us to import the rest of what we need from the standardized Beach directory structure (as opposed to the $PATH based structure of Python).

The next  import we need is the StatelessActor, which gives us the simplified API we need to inherit from. 

Finally we import the `_xm_` function. This function (along with its sibling, `_x_`) is a simplified accessor to go through the message data-structures. The `_xm_` gives you an X-Path-like accessor, returning a `list` of elements matching in the JSON data. It works because all tags (or keys in JSON-land) in LC have the limitation of not containing the '/' character. The `_x_` accessor does the same, but instead of returning a `list` of all matching elements, it returns the first matching element, or None.

```
from beach.actor import Actor
import re
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )
```

## The Class declaration

The name of the Class MUST be the same as the file as it's a Beach standard. Our class must also inherit from the StatelessActor class we imported before.

```
class WinSuspExecName ( StatelessActor ):
```

## The initialization entry points

The StatelessActor parent class defines the `init( parameters )` and `deinit()` functions to be used to initialize anything you need in the actor. The `parameters` argument to the `init` function is used to provide any of the JSON parameters provided when the actor was created. As a standard, we call the super-class' `init` function to initialize some StatelessActor-specific structures.

```
    def init( self, parameters ):
        super( WinSuspExecName, self ).init( parameters )
        self.susp = re.compile( r'.*((\.txt)|(\.doc)|(\.rtf)|(\.jpg)|(\.gif)|(\.pdf)|(\.wmi)|(\.avi)|( {5}.*))\.exe', re.IGNORECASE )
        self.rtlo = re.compile( r'.*\xE2\x80\x8F.*' )
```

## The processing entry point

The main entry point to the class is the `process( msg )` function. It receives a single parameter, an ActorRequest (see Beach for details) who's data element contains a 3-tuple of routing information, the actual event from the sensor and a metadata `dict` of metadata extracted from the sensor in a generic form. This is why the first line of the `process` function is usually like the one below, expanding the 3-tuple.

```
    def process( self, msg ):
        routing, event, mtd = msg.data
```

## The detection reporting

Finally, the core behavior of a Stateless Detection is to... generate detections. These are created and reported by the return value of the `process` function. The return value is an array of detects, where a detect is a 2-tuple.

This 2-tuple's first element is a `dict` of the detect data, which often is simply the event itself, but feel free to add your own extracted information in there for later use (see Hunters). The second element of the detect 2-tuple is a `tuple` of commands that should be sent back to the sensor who's message we are currently analyzing. Each command is itself a `tuple` of the command and its parameters as used in the `admin_cli.py` command line interface.

It makes for a lot of embedded tuples so make sure to keep a clear alignment in your code to make it easier to understand what's what.

```
detects.append( ( event, ( ( 'remain_live', 60 ),
                           ( 'history_dump', ),
                           ( 'exfil_add', 'notification.FILE_CREATE', '--expire', 60 ) ) ) )
```

## The logic as a whole

Now you can see that as a whole, this Stateless Actor will look for elements named `base.FILE_PATH` in the first level of the event, and for each of those, it will try to match a regular expression. In this case the regular expression shows the pattern of a file named `something.txt.exe` or using the RightToLeftOverride unicode character, which is the pattern of an executable trying to hide the fact it's an executable.

If the regular expressions match, a new detect is generated from the event, and these tasks are sent:
* Remain live (constantly in contact with the cloud) for the next 60 seconds.
* Dump the historical buffer kept on the sensor (which includes all events in the sensor that were not sent back to the cloud during normal operation, this can be a lot of data) back to the cloud.
* Start sending back to the cloud all file creation events for the next 60 seconds.

```
from beach.actor import Actor
import re
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )

class WinSuspExecName ( StatelessActor ):
    def init( self, parameters ):
        super( WinSuspExecName, self ).init( parameters )
        self.susp = re.compile( r'.*((\.txt)|(\.doc)|(\.rtf)|(\.jpg)|(\.gif)|(\.pdf)|(\.wmi)|(\.avi)|( {5}.*))\.exe', re.IGNORECASE )
        self.rtlo = re.compile( r'.*\xE2\x80\x8F.*' )

    def process( self, msg ):
        routing, event, mtd = msg.data
        detects = []
        for filePath in _xm_( event, '?/base.FILE_PATH' ):
            if self.susp.match( filePath ) or self.rtlo.match( filePath ):
                detects.append( ( event, ( ( 'remain_live', 60 ),
                                           ( 'history_dump', ),
                                           ( 'exfil_add', 'notification.FILE_CREATE', '--expire', 60 ) ) ) )
        return detects
```