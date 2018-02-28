## Loading and unloading capabilities (detections or hunters)

### Where are all the detection?!
They're in the [lc_detection repo](https://github.com/refractionPOINT/lc_capabilities).
Those are detections that are vetted, but that doesn't mean that's all there is.
Feel free to fork that repo, contribute and experiment with new wild detections.
If you need a hand let us know in the [Google Group](https://groups.google.com/d/forum/limacharlie) or better the [Slack channel](http://limacharlie.herokuapp.com/).

Remember that the instructions below refer to the URL of detections and patrols and those are the *raw* URL like:

```
https://raw.githubusercontent.com/refractionPOINT/lc_capabilities/master/stateless/TestDetection.py
```

### Loading
1. In the LC web ui, go to the "Capabilities" section from the side menu.
1. Under the "Load Capabilities" Enter the URL of the raw capability directly. (This can be a URL to a detection itself or to a patrol that will load multiple detections.)
1. Enter a user-defined (unique) name for the capability or patrol.
1. After a few seconds the capability should load and be visible below.

### Unloading
1. In the LC web ui, to to the "Backend Config" section from the top menu.
1. Click on the "Load/Unload Capabilities" link at the top.
1. In the capability name field associated with the "remove" button, enter the user-defined name to remove. This is the name set when adding the capability. It is also visible in the capability listing below.