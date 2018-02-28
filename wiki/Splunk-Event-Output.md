# File Output
Events and detect can be output to file, which can then easily be sucked in by Splunk or other log aggregation platforms. 

This feature is controlled by the `global/logging_dir` configuration. You can disable by setting this configuration to "" (empty string). This value otherwise represents the directory where the files should be stored.

This configuration can be set through an RPC from the command line like this:

```
python -m beach.beach_cli beach.conf --req-realm hcp --req-cat "c2/deployment" --req-cmd set_config --req-data "{'conf' : 'global/logging_dir', 'value' : '/path/to/some/dir/', 'by' : 'yourUser@company.com' }" --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903
```