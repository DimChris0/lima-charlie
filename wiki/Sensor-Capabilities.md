# Sensor Capabilities

The following is a list of detection or telemetry generation done on the sensor.

We wouldn't mention the exfil of events as a capability, but it's awesome in LC. The sensor can be configured
at runtime (through a Profile) to exfil different events. The events are always generated (and used) within the
sensor, but sending it all to the cloud would be a lot of data. The cloud has the capability to select which
ones to send back. This means you can exfil the basic most of the time, but if the cloud detects something 
suspicious, it can tell the sensor to start sending a bunch more events back, from file io to individual module
loads.

| Name | Description | Platform |
| ---- | ----------- | -------- |
| ProcessTracker | Generates events for processes starting or stopping. | All |
| DNSTracker | Generates events on new DNS requests. | Windows |
| CodeIdentity | Generates an event for every unique executable module loaded, including hash and signature (on Windows only). | All |
| NetworkTracking | Generates events for TCP and UDP "connections" starting and stopping, includes owner process id. | All |
| HiddenModuleDetection | Constantly goes through the memory of all processes looking for traces of modules executing covertly. | All |
| ModuleTracker | Generates events for modules loading and unloading in processes. | All |
| FileTracker | Generates events on file creation and deletion. | OSX & Windows |
| NetworkProcessSummary | Generates events summarizing the first X network connections created by every process. | All |
| HistoryDump | Keeps rolling buffer of all events generated in the sensor and dumps them upon request. | All |
| ExecOutOfBounds | Generates a detection when execution is detected executing outside the bounds of known modules. Essentially code injection or shell code. | Windows |
| MemDiskMismatch | Generates a detect when a significant mismatch between a module in memory and on disk. Essentially process hollowing. | All |
| YaraDetection | Constantly looks through memory and modules loading from disk for a set bundle of Yara signatures. | All |
| FileOps | List of various file related functions like get, delete, move, getInfo, hash etc. | All |
| MemoryOps | List of various memory related functions like get (read specific memory chunks from processes), or string search. | All |
| OsOps | List of various OS related functions like getServices, getProcesses, getAutoruns etc. | All |
| DocCache | Cache documents created in path or with extension. Generates stub events for every document created (without content), or retrieve doc by file pattern or hash with content later. | Windows & OSX |
| UserTracker | Emits events whenever a new user is observed for the first time. Can be used to do anomaly detection who who logs in where. | All |
| FileTypeTracker | Emits events the first time a process accesses a file of a specific type (like .doc). Can be used to detect anomalies like smss.exe reading from a Word document. | Windows & OSX |