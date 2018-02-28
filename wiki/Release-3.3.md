# Release 3.3

## Changes
### Sensor
* Stability fixes on 32 bit Windows.
* Network Summaries only generated when there are network events for the process.
* Changes to sensor to enable automated testing.
* Better indication around Power On Self Tests.
* Windows sensor now logs to stdout as well as DebugView.
* Normalizing sensor pack names to Linux instead of Ubuntu since the sensor runs (and is tested) on at least Ubuntu and CentOS.
* HCP now sends a hash of its main file on disk on new connections, will be used for automated HCP upgrades.
* Debug sensor can now load manually multiple modules simply by repeating the `-n modId -m modFile`.
* Cleaner handling of partial kernel acquisition driver installation should result in less glitches.

### Cloud
#### Highlights
* Adding simple per-Org Webhooks for detects and investigations to enable simple integrations.
* Adding a page to find machine by IP / Time range (useful for correlation with other IP-based systems).
* Adding a Bulk Object search page, dump newline separated objects and get results for all, useful for IoC checks.
* Adding sensor tagging system, manual as well as automated in stateless analytics, tags also included in all sensor events through the system, also search sensors by tag.
* Capabilities now persist across cloud restarts.
* Adding an Opt-In usage metrics reporting (anonymized) to LC developers.
#### Others
* Tons of fixes and enhancements to Beach will result in much better performance and more resiliency.
* Enabling full event logging to file (with file rotation) by default.
* Fixing dropped connections issue to Cassandra.
* Adding tracking of sensor bytes transferred. **Requires new tables, see schema**
* Now detections page displays all detections not just investigations.
* Adding a simple framework to run simulated sensors to test load on a cloud.
* Enabling re-use of the email-confirmation link to make for a simpler new user flow.
* Tracking original events that relate to specific Objects. **Requires a data schema change**
* Adding charts to LC dashboard showing current sensor breakdown.
* Showing hostname in Object search.
* Congestion now detected and reported in logs.
* Rate limiting per sensor to help alleviate sensors going crazy.

## Schema Update
```
use hcp_analytics;
CREATE CUSTOM INDEX fn_tag_contains ON sensor_tags ( tag )USING 'org.apache.cassandra.index.sasi.SASIIndex' WITH OPTIONS = { 'mode': 'CONTAINS', 'case_sensitive': 'false' };
ALTER TABLE sensor_tags DROP uid;
ALTER TABLE sensor_tags ADD frm varchar;
DROP TABLE tags;
DROP TABLE obj_org;
CREATE TABLE obj_org
(
  id varchar,
  oid uuid,
  ts timestamp,
  sid uuid,
  eid uuid,
  PRIMARY KEY( id, oid, ts, sid )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;
CREATE TABLE sensor_transfer(
  sid uuid,
  ts timestamp,
  b int,
  PRIMARY KEY( sid, ts )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;
CREATE TABLE sensor_ip(
  sid uuid,
  oid uuid,
  ts timestamp,
  ip varchar,
  PRIMARY KEY( ip, oid, ts, sid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;
```