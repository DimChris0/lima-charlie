# Exfil Control

Controlling the data coming out of the LC sensor can be as simple or customized as you want. The general behavior is controlled mainly through the HBS profile. A sample profile is found in `/cloud/beach/production_hbs.profile`.

## Exfil events
Exfil events are events that, when they are generated, will be automatically added to the exfil queue to be sent to the LC cloud. These events are set by adding the event type to the list of Notifications in the config of the Exfil collector in the HBS profile. This way you can have a basic set of exfil applied to different ranges of sensors.

Additionally, you can add an event type to this list for a certain number of seconds at run time through the `exfil_add` command in the CLI and indirectly through a Hunter or other Detect type that can do tasking. So for example the command `exfil_add notification.FILE_CREATE --expire 60` would add the FILE_CREATE events to the list of events automatically sent to the LC cloud for the next 60 seconds.

## History
It is important to know that because an event is not set to Exfil or Critical doesn't mean it's lost after being generated. The LC sensor keeps a circular buffer of events that were generated but not sent as Exfil or Critical. This list, being a circular buffer, is bounded in number of events and total size as to not exhaust resources of the host.

This history can then be dumped using the CLI / tasking command `history_dump`. This command will force the sensor to send back the entire history collected so far, just once. The length back in time the history reaches will vary, on a busy system it will be shorter than on a quiet system. Dumping history is usually a corner stone of response from Hunters or other forms of Detects since it allows you to get a lot of context around an event that occurred in the recent past, giving you an edge to investigate and track a potential attack.
