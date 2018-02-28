## Common Helpful RPCs
Each of the following command lines refers to `beach.conf`, adjust it to point to your beach cluster config file.

Set retention time for various types of data for an org:
```
python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "c2/ident" --req-cmd set_retention --req-data "{'ttl_events' : 2419200, 'ttl_short_obj' : 2419200, 'ttl_atoms': 2419200, 'ttl_detections' : 2419200, 'ttl_long_obj' : 10713601, 'oid' : '04a9d860-bcd3-11e6-a56f-8dc8378d2ca2' }" --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903
```

Reset a user's credentials, will outpout a temporary password:
```
python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "c2/ident" --req-cmd reset_creds --req-data "{'email': 'maxime@refractionpoint.com', 'by' : 'maximelb@google.com' }" --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903
```

Set the modeling level for how much data gets stored in Cassandra:
```
python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "c2/deploymentmanager" --req-cmd set_config --req-data "{ 'conf' : 'global/modeling_level', 'value' : '10', 'by' : 'admin' }" --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903
```

Get general counters from an actor:
```
python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "" --req-cmd z
```

Disable and enable 2-Factor-Authentication:
```
python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "c2/deploymentmanager" --req-cmd set_config --req-data "{ 'conf' : 'global/2fa_mode', 'value' : 'off', 'by' : 'admin' }" --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903

python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "c2/deploymentmanager" --req-cmd set_config --req-data "{ 'conf' : 'global/2fa_mode', 'value' : 'on', 'by' : 'admin' }" --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903
```