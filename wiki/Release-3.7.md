# Release 3.7

## Changes
* Network Segregation, isolate a host from the network (leaving the sensor comms working) and rejoin network via commands.
* Detection Lambdas, added event types supported. Doc is [here](https://github.com/refractionpoint/limacharlie/wiki/Detect-Lambdas).
* Capabilities refactored into a simple Detection & Response model that make it easier to use.

## Database Updates
```
ALTER TABLE hbs_profiles ADD tag varchar;
COPY hbs_profiles ( aid, tag, cprofile, oprofile, hprofile ) TO '/tmp/hbs_profiles.txt' WITH HEADER=true AND DELIMITER='|' AND NULL=' ';
DROP TABLE hbs_profiles;
CREATE TABLE hbs_profiles(
  aid varchar,
  tag varchar,
  cprofile blob,
  oprofile varchar,
  hprofile varchar,
  PRIMARY KEY( aid, tag )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;
COPY hbs_profiles (aid, tag, cprofile, oprofile, hprofile ) FROM '/tmp/hbs_profiles.txt' WITH HEADER=true AND DELIMITER='|' AND MAXBATCHSIZE=10;


CREATE TABLE stateful_states
(
  sid uuid,
  state_data blob,

  PRIMARY KEY( sid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;
```