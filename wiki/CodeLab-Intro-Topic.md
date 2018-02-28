# CodeLab Intro Topic
Read this page before moving on to the other code labs as it covers basic mechanisms used when developing for the LC backend.

## The Detection Story
In LimaCharlie, 3 terms are very important to separate in your head:

1. **Events:** that's just the raw telemetry coming in from the sensors. Some of it is always sent back to the cloud (as per the Sensor Configs in the web ui), the rest gets stored locally in the sensor and can be retrieved by issuing a *history_dump* command, more on that later.

1. **Detections:** those are the basic units of analysis in the cloud. Think of them like Events, except they're "suspicious" events. The cloud runs detection modules and extracts / generates Detections from Events. We cannot necessarily tell that the Detections are "bad" or not. To do this, we need to investigate those possible problems.

1. **Hunters:** they serve as the second layer of the detection story. Think of them as the police investigators whereas the Detections were the police patrolling the neighbourhood. Each Hunter has a list of types of Detection it knows how to investigate. When one of those Detections occur, the relevant Hunter(s) will receive a copy and will immediately begin their investigation. As a Hunter, you get access to the entire Model (stored, pivoted data in the cloud) and the Sensor (with which you can interactively issue commands and get data). Hunters produce an Investigation, which is a more complete rollup of the Detection along with the activity, actions and data gathered by the Hunter.

## Getting in the Flow
### Stateless
Creating stateless detection actors, that is detections that are based on the context of a single piece of telemetry, requires subscribing your actor to one or more "categories" in Beach.

The general pattern for the topics is this:
> analytics/stateless/[platform]/[event]/[detection_name]/[version]

The [platform] is one of "common", "windows", "osx" or "linux". Common receives events from all platforms.
The [event] is the event type, for example "notification.CODE_IDENTITY" would receive all events with hashes and digital signatures from the host.
The [detection_name] is just the name you give your detection.
The [version] is not strictly required but encouraged to help you test various versions simultaneously.

For example, the category "analytics/stateless/common/notification.CODE_IDENTITY/virustotalknownbad/1.0" would receive all CODE_IDENTITY events for all platforms for the detection "virustotalknownbad" version "1.0".

### Stateful
The stateful detection is more complex and therefore does not rely on the category alone to receive the events. The pattern for stateful detection is:
> analytics/stateful/modules/[platform]/[detection_name]/[version]

The components are the same as for stateless, the difference is that stateful detection will receive copies of all events from hosts on the relevant platform, sharded by the number of instances of the stateful detection actor that are spawned. This will become more obvious later on.

### Hunter
Hunters rely even less on the category, the pattern is:
> analytics/hunter/[hunter_name]/[version]

The exact Detections a Hunter subscribes to (for investigation) is actually located in the code of the Hunter itself. This will also become more obvious later on.

## Wrap-up
Stateless Detections are by far the easiest to implement whereas Stateful uses a more complex framework and Hunters generally require more code.
