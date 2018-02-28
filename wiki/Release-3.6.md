# Release 3.6

## Changes
* Detection Lambdas, create detections and mitigation straight from web UI in simple lambda-like expressions. Doc is [here](https://github.com/refractionpoint/limacharlie/wiki/Quick-Detects).
* Kernel Acquisition fix when unloading an extension that failed to initialize.
* General robustness of various cloud components.
* Streamlining of Cassandra storage, clearer flagging of Cassandra requiring more power.
* Adding event_time to routing.
* Adding a `modeling_level` configuration to reduce (or disable) the modeling stored in Cassandra, this greatly increases performance (see [here](https://github.com/refractionpoint/limacharlie/wiki/Common-helpful-utils) to adjust).
* General bug fixes to web UI.
