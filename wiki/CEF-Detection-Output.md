# CEF Detect Output
Detections can be emitted to Common Event Format which is understood by various SIEMs. This is done by writing the detection information in the CEF format to Syslog.

# Actor Configuration
The Actor that provides this is the [CEFDetectsOutput.py](https://github.com/refractionPOINT/limacharlie/blob/develop/cloud/beach/hcp/analytics/CEFDetectsOutput.py) Actor. It supports the following arguments:

```beach_config```: the path to a Beach config file, needed for the moment to access the Python API to our models.

```scale_db```: the hostname (or list of hostnames) to Cassandra seed nodes.

```siem_server```: a variable for use by the syslog handler to know where to send the records.

```lc_web```: the DNS to use to represent the LC web interface in detections, will be used to construct the URL to see the detailed report.

# Scope
Because CEF is so limited and simple, only the initial detection event is sent to this output for now. Included in the alert is a link to the LC web ui where the full live result of the investigation is available. This is because when a detection is created, there is often an asynchronous investigation done by a Hunter that is started. This investigation can have many steps and information it reports which could not be handled by a SIEM generically.