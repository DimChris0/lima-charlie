# Release 1.0 Alma

## Features
* Event Timestamps now down to milliseconds.
* Process owner now also included in NEW_PROCESS events on Windows (so now on all platforms).
* Output detections to Common Event Format (CEF).
* Output events to file log, supporting Splunk and LogStash.
* Adding the concept of Atoms, providing strong linkage between events.
* Adding an Explorer to the web ui which allows you to navigate and visualize related events.
* Comms over persistent TCP connections brings automation to milliseconds!
* Web UI allows the loading of detections (stateless, stateful and hunters) dynamically and directly from an online repo like GitHub.
* Windows file notifications from the kernel associated with PIDs.
* New simpler Hunter framework provides super easy automation of investigations interactively from the sensor and the cloud sources.
* Dynamically load external capabilities from URLs.
* Detection capabilities moved to a new simpler external GitHub repo.
* You can now set cloud components to target specific branches straight from the official repo.