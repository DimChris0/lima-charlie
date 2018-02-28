# Stateless Detections

Stateless detections generate detects from the context of a single event, no correlation, making them the simplest detections.

| Name | Description | Platforms |
| ---- | ----------- | --------- |
| WinSuspExecLoc | Detects execution from suspicious locations. | Windows |
| MacSuspExecLoc | Detects execution from suspicious locations. | OSX |
| VirusTotalKnownBad | Detects hashes known to be bad from VirusTotal, based on a parameter threshold. | All |
| ExecNotOnDisk | Detects modules loading that cannot be found on disk. | All |
| HiddenModules | Generates a detect based on a HIDDEN_MODULE event from sensors. | All |
| HollowedProcess | Generates a detect based on a MODULE_MEM_DISK_MISMATCH event from sensors. | All |
| WinOobExec | Generates a detect based on a EXEC_OOB event from sensors. | Windows |
| WinSuspExecName | Detects execution of executables trying to appear like harmless documents. | Windows |
| YaraDetects | Generates a detect based on a YARA_DETECT event from sensors. | All |
| ShadowVolumeTampering | Generates a detect when someone tampers with a Windows Shadow Volume. | Windows |
