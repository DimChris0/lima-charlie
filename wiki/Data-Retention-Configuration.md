As of LimeCharlie 3.5.2 the data retention policies are set by default to 7 days in the database. 

## Retention types
* `ttl_long_obj`: How long most long-lived Objects should be stored. Long lived Objects include process name, file hash etc.
* `ttl_short_obj`: How long most short-lived Objects should be stored. Short lived Objects include command lines, domain names and ports. This ttl is usually shorted because the number of objects that match are very high.
* `ttl_events`: How long the raw events should be stored.
* `ttl_atoms`: How long Atoms should be stored. Atoms are the data structure that makes the Explorer view (connected graph) possible. This data is stored separately so they can be flushed while keeping the events themselves.
* `ttl_detections`: How long the detection data is stored.

## Modifying the Data Retention Time
### Through an RPC

```
python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "c2/ident" --req-cmd set_retention --req-data "{'ttl_events' : 2419200, 'ttl_short_obj' : 2419200, 'ttl_atoms': 2419200, 'ttl_detections' : 2419200, 'ttl_long_obj' : 10713601, 'oid' : '04a9d860-bcd3-11e6-a56f-8dc8378d2ca2' }" --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903
```
### Through the database
1) Authenticate in to the Cassandra DB Console
2) Select the hcp_analytics keystore

`use hcp_analytics`

3) Identify the organization ID to modify

`select oid, name from org_info`

4) Run the following update command to increase or decrease the length of time.

_NOTE: All TTLs are stored in seconds. _

_NOTE: This example changes the data retention from 7 days (Default) to 30 days._

_NOTE: ttl_long_obj is default is 31 days._ 

`UPDATE org_info 
SET 
ttl_events = 2592000, 
ttl_short_obj = 2592000, 
ttl_long_obj = 2678400, 
ttl_atoms = 2592000, 
ttl_detections = 2592000 
WHERE 
oid = <Organization ID>`

### Future improvements
There are plans to make this modifiable through the Web UI in the future. 

