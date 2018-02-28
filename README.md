# LIMA CHARLIE
<img src="https://lcio.nyc3.digitaloceanspaces.com/rp.png" width="150">
<img src="https://lcio.nyc3.digitaloceanspaces.com/lc.png" width="100">

## What is LimaCharlie
LC is an Open Source, cross-platform (Windows, MacOS, Linux ++), realtime Endpoint Detection and Response sensor.
The extra-light sensor, once installed on a system provides Flight Data Recorder type information (telemetry on all aspects of the system like processes, DNS, network IO, file IO etc).

The configuration of the sensor can be updated at runtime to send back specific types of events. The sensor also caches the detailed events to be sent back to the cloud on request.
In addition to advanced "passive" collection of telemetry, the sensor can also be tasked with many investigation actions (like reading process memory) and mitigations (like network-isolate the host).

Ultimately, LC is a highly configurable platform to deliver endpoint capabilities.

## How to Use LimaCharlie?
Main support and development is provided by [Refraction Point](https://www.refractionpoint.com) and its LimaCharlie Enterprise (LCE) platform. The LCE platform differs from the Open Source community
branch by its more robust architecture, larger feature set, complete automation package and its management interface (fully REST controlled and appliance-delivered).

The community edition is still available through GitHub but it is no longer officially supported.

*Talk to us on the [LimaCharlie Slack Community](http://limacharlie.herokuapp.com/)*

*Stay up to date with new features and detection modules: [@rp_limacharlie](https://twitter.com/rp_limacharlie)*

*For more direct enquiries, contact us at info@refractionpoint.com*

## Who Uses LimaCharlie?
*** Due to the sensitivity of their security toolset, several other organizations prefer to keep a lower profile. Contact us if you would like to inquire about specific organization types of using LC. ***

### Loki Labs
<p align="center">
  <a href="https://lokilabs.io"><img src="https://raw.github.com/refractionPOINT/limacharlie/develop/doc/users/lokilabs.png" width="200"></a>
</p>
Founded by former members of the US intelligence & military community, Loki Labs' security engineers previously held elite, highly-specialized roles working in support of offensive and defensive cybersecurity efforts. As a result, the technical team possess unique training, experience, capabilities, and insight of the tools and tactics used by adversaries to gain access to targets of interest.
<p align="center">
  <i>"In an endless sea of endpoint agents, LC stands head-and-shoulders above competing open-source and fee-based tools at a fraction of the operating cost. LC's APT detection, threat mitigation, and interoperability are best-in-class and this is why its our agent of choice."</i>
</p>

### Jigsaw Security
<p align="center">
  <a href="https://www.jigsawsecurityenterprise.com"><img src="https://raw.github.com/refractionPOINT/limacharlie/develop/doc/users/jigsaw-security.png" width="200"></a>
</p>
Jigsaw Security is as much of a concept as it is a company. Combining strategic partnerships with the right engineers to provide best in class security software, consulting, management and delivery. Our team started in DoD consulting and Military service and still serves through the development of strategic partnerships with Government and Private Sector to keep industries safe from Cyber and Physical threats and challenges.

### MalwareLab.co.uk
Live Malware Analysis performed thinking Out of the (Sand)Box.
<p align="center">
  <a href="http://malwarelab.co.uk"><img src="https://raw.github.com/refractionPOINT/limacharlie/develop/doc/users/the_malware_lab.png" width="200"></a>
</p>

### Trials

#### BAE Systems
<p align="center">
  <a href="http://www.baesystems.com/"><img src="https://raw.github.com/refractionPOINT/limacharlie/develop/doc/users/bae.jpg" width="200"></a>
</p>

## Core Values
LIMA CHARLIE's design and implementation is based on the following core values:
* Reduce friction for the development of detections and operations.
* Single cohesive platform across Operating Systems.
* Minimize performance impact on host.
