# Creating a Detection

## Creating the Actor
Creating a new detection implies creating a new Actor that we will then load into our beach cluster.
The first step is creating the Actor. So create a file and name it the same name as the Actor / Detection in it. For example, we will re-create the WinSuspExecName Detection which detects suspicious executable names on Windows, so we will call the file WinSuspExecName.py.

## Metadata
At the top of the file, we will add a small metadata block that will help LC figure out what this Actor does. Here is a sample metadata block:

    ###############################################################################
    # Metadata
    '''
    LC_DETECTION_MTD_START
    {
        "type" : "stateless",
        "description" : "Detects executions with suspicious names on Windows.",
        "requirements" : "",
        "feeds" : [ "notification.NEW_PROCESS",
                    "notification.CODE_IDENTITY" ],
        "platform" : "windows",
        "author" : "maximelb@google.com",
        "version" : "1.0",
        "scaling_factor" : 1000,
        "n_concurrent" : 5,
        "usage" : {}
    }
    LC_DETECTION_MTD_END
    '''
    ###############################################################################

The "type" there is "stateless" because this first Detection is a stateless one, we can determine if this Detection triggers based purely on the content of one event at a time.

Description is fairly obvious.
Requirements should be used as a human readable field to describe if your detection has special requirements like non-standard libraries etc.

Feeds lists the events which should be fed to the Detection.

Platform indicates the platform whose events can be processed by this Detection, so one of "windows", "osx", "linux" or "common" (for all).

Author is the email address where the author can be reached at.

Version, obvious.

Scaling Factor is used when your Detection is deployed as part of a Patrol. A Patrol ensures that your Detection Actors are always running, but also ensures that the correct number of instances are created in the Beach cluster to support the demand. The factor is the number of hosts that can be served by a single instance of this detection. It doesn't have to be very accurate as users can override this or enable other control methods that dynamically add or remove instances.

n_concurrent is the number of requests that this actor can serve concurrently. For most stateless Detections this can be quite high since the Actor is not relying on external systems or logic that requires mutually exclusive resources.

Usage lists the key and values this actor can use as external parameters, in this case we don't have any.

## Imports
Now we need to import the basics of a Beach Actor.

    from beach.actor import Actor

This Actor import is a hard requirement, it will provide you with basic functionality within Beach.

    import re

We will need regular expressions and *re* is a standard library, so we'll straight import it.

    StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )

When importing Python classes within Beach, an alternate import method is provided. This alternate method does some magic under the hood to allow you to import relative files within the cluster but also remote files using a URL format like: *https://my_lc_repo/detections/CoolNewDetection.py*.

In this case, the above line imports the *StatelessActor* class found in the *Detects*(.py) file. This class will be used to inherit from, it will give you all the goodies needed by stateless Detections.

    _xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )

Here we import the *\_xm_* function. It's a funny name for a very useful and simple function. The *\_xm_* function will allow you to use a path akin to XPath in XML through a JSON object and will return to you a list of all the results. It also supports wildcards like * which is super useful! The *\_xm_* function is located in the *utils/hcp_helpers*(.py) file. Note that the *\_x_* function is also often used, it's the same as the *\_xm_* function but returns the first element (or None).

## Overhead

Now is the time to write the overhead code for the Detection:

    class WinSuspExecName ( StatelessActor ):

The name of your Detection is the name of your class and is the name of your file...

        def init( self, parameters, resources ):
            super( WinSuspExecName, self ).init( parameters, resources )

This init function gets called when your Actor starts. Call the Super's init function with *parameters* and *resources* and then initialize any structures or variables that are constant to your Detection.

The *parameters* variable is a dictionary containing any user provided parameters (remember the metadata block above). The *resources* variable usually holds a dictionary of user-defined Beach categories to actual Beach categories. It serves as an indirection layer but is unlikely relevant to you for now.

            self.susp = re.compile( r'.*((\.txt)|(\.doc)|(\.rtf)|(\.jpg)|(\.gif)|(\.pdf)|(\.wmi)|(\.avi)|( {5}.*))\.exe', re.IGNORECASE )
            self.rtlo = re.compile( r'.*\xE2\x80\x8F.*' )

In this case, we will need to search for two regular expressions, so we might as well compile them here. The regular expressions represent two patterns that if matching an executable name and path are likely suspicious. The first one looks for things like myfile.doc.exe while the second looks for the [RTLO technique](https://blog.malwarebytes.com/cybercrime/2014/01/the-rtlo-method/).

## Core

And now the core of our Detection:

    def process( self, detects, msg ):

The *process* function is the entry point that will get called with every relevant event you specified, in real time. The parameters to it are *detects* which is an object where you can add things you've detected and the *msg* parameter is the actual Event.

        routing, event, mtd = msg.data

First thing we do is unwrap the Event, we only really care about the data which is a tuple of routing information (a dict), an event content (a dict) and mtd (a dict). The routing will tell you which sensor this came from and a few other details. The event is the actual event content as you'd see it in the web ui. The mtd is the metadata (Objects) that were extracted from this event, more on this later.        

        for filePath in _xm_( event, '?/base.FILE_PATH' ):
            if self.susp.match( filePath ) or self.rtlo.match( filePath ):

So for each *base.FILE_PATH* under the first level of event (since event is always a dict with one key, the key is the event type, like *notification.NEW_PROCESS*). We're looking for all paths in the first level of the event, whatever event type this is. If it matches either one of our regular expressions:

                detects.add( 90,
                             'suspicious executable name',
                             event )

[Add a new detection](https://github.com/refractionPOINT/lc_cloud/blob/master/beach/hcp/Detects.py#L40), the first parameter is a priority (integer, higher number is more important), a summary (human readable string to explain) and the detection information, which is a dict containing whatever you want to report as a detection. Usually the detection information parameter will just be the event itself unless the root logic of the detection is not obvious or requires some kind of processing on the event to become obvious or useful.

## Final Product
That's it, your detection should look like this:

    ###############################################################################
    # Metadata
    '''
    LC_DETECTION_MTD_START
    {
        "type" : "stateless",
        "description" : "Detects executions with suspicious names on Windows.",
        "requirements" : "",
        "feeds" : [ "notification.NEW_PROCESS",
                    "notification.CODE_IDENTITY" ],
        "platform" : "windows",
        "author" : "maximelb@google.com",
        "version" : "1.0",
        "scaling_factor" : 1000,
        "n_concurrent" : 5,
        "usage" : {}
    }
    LC_DETECTION_MTD_END
    '''
    ###############################################################################
    
    from beach.actor import Actor
    import re
    StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
    _xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )
    
    class WinSuspExecName ( StatelessActor ):
        def init( self, parameters, resources ):
            super( WinSuspExecName, self ).init( parameters, resources )
            self.susp = re.compile( r'.*((\.txt)|(\.doc)|(\.rtf)|(\.jpg)|(\.gif)|(\.pdf)|(\.wmi)|(\.avi)|( {5}.*))\.exe', re.IGNORECASE )
            self.rtlo = re.compile( r'.*\xE2\x80\x8F.*' )
    
        def process( self, detects, msg ):
            routing, event, mtd = msg.data
            
            for filePath in _xm_( event, '?/base.FILE_PATH' ):
                if self.susp.match( filePath ) or self.rtlo.match( filePath ):
                    detects.add( 90,
                                 'suspicious executable name',
                                 event )

## Installing the Detection
First thing first, copy your file to the LC server or to a publicly accessible location via a URL handler (like http://, https://, ftp:// or file://). Make sure the file is readable by the user running your LC cloud on the server.

Log in to the web ui as an administrator (admin@limacharlie by default).

In the main menu (top left), select Capabilities.

In the URL field, enter the file:// (or other) path to your Detection.

You can ignore the Patrol Content field for now, it can be used to run an entire Patrol via the form.

In Name, put a unique capability name you want to represent your Detection with. You will use that later on to unload it.

Finally in Arguments you could put some JSON parameters to your Detection if you wanted, it would get passed to your init() function.

Hit the Add Capability button. It might take a few seconds, and then you should see an entry below with the information about your new Detection.

It might take up to a minute for the data to start flowing to your new Detection. Beach is designed as a distributed eventually-consistent cluster, so the routing needs to propagate.

## Debugging
The best way to debug is to use *self.log( "some message here" )* calls in your Detection. These will get sent to your syslog (/var/log/syslog on default Ubuntu). So you can see what's going on that way.

## Next Steps
Remember that the Detections are the first step of the story in LC. The next step is Hunters that can investigate those Detections.

That being said, it's also possible to output Detections along with the normal telemetry using something like the [FileEventsOutput](https://github.com/refractionPOINT/lc_cloud/blob/master/beach/hcp/analytics/FileEventsOutput.py) Actor.
