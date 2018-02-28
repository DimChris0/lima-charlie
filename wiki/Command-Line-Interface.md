# Command Line Interface

The `admin_cli.py` is the main interface to configure the cloud and to task sensors. It is itself an interface over
`admin_lib.py` which can be used to do the same things programatically in Python.

When starting the CLI, the first thing to do is to `login`. A simple login with the _cli config will allow you to
configure the cloud, but not task the sensors. To task the sensors you will also have to use the "-k" option and
to provide the HBS key. When the HBS key is provided and loaded, a "*" will appear in the command line prefix. 

A `help` command will provide you the options for all the commands, however there are a few parameters that are
global and are worth mentioning.
* The `chid <sensorId>` command will change the context (like a chdir) of the sensor(s) (can be masked) where the
   tasks are sent, this is a "permanent" change.
* The `-! <sensorId>` in a tasking command (to a sensor, not cloud config) will send the task to the sensor(s) 
  (can be masked) for this one command only, this is a change for this single command.
* The `-@ <investigationId>` command attaches an `hbs.INVESTIGATION_ID` tag to the command, and this tag is mirrored
  back to the cloud with the response. This allows you to attach IDs tracking the purpose of commands sent.
* The `-x <expirySec>` sets a time limit for which the command is valid. This expiry means that if the sensor
  receives the command after that time, it will simply ignore it.
