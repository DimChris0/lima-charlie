# Release 3.5

*Note that there is no sensor pack released with 3.5 as changes to the sensors only affect Power On Self Test and not runtime behavior.*

## Changes
* Create, delete and tag using Installation Keys.
  * You can now create as many Installation Keys as you want through the UI, and delete them (like revoking an installer).
  * Each Installation Key can have a description and a list of tags that should be applied to sensors enrolling using it.
* Appliance a bit easier to use.
  * Adding a check for Cassandra being online for `start_node.py` and `join_cluster.py`.
  * Adding a `start_all_in_one.py` script to run both `start_node.py` and `start_ui.py` in one shot.

## Schema Update
```
use hcp_analytics;
ALTER TABLE hcp_whitelist ADD description varchar;
ALTER TABLE hcp_whitelist ADD tags varchar;
```
