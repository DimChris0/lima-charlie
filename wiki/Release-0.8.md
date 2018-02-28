# Release 0.8

## Features
* Yara Collector. Can scan disk and memory continuously for Yara signatures.

## Notes
* Yara signature support may require to bump the max_allowed_packet in MySql to a higher value to be able to hold potentially larger Yara signature files in tasking. Additionally, tasking datatype in MySql has been moved from BLOB to LONGBLOB to be able to hold larger tasking, this may require you to drop-recreate the table in question with the new datatype.