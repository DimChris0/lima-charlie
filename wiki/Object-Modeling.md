# Object Modeling

We extract Objects from all events coming back from the sensors. Objects are characteristics of telemetry for example:
- RELATION
- FILE_PATH
- FILE_NAME
- PROCESS_NAME
- MODULE_NAME
- MODULE_SIZE
- FILE_HASH
- HANDLE_NAME
- SERVICE_NAME
- CMD_LINE
- MEM_HEADER_HASH
- PORT
- THREADS
- AUTORUNS
- DOMAIN_NAME
- PACKAGE
- STRING
- IP_ADDRESS
- CERT_ISSUER

We do a few different things with these Objects.

The events are parsed and passed along to all the detection modules. This means a module you write doesn't have to know about the details of all the event types it's looking at to be able to evaluate parts of their content.

We also ingest all the Objects into the scale-db. But we don't stop there, when we ingest them, we use an enhanced model where we store the Object itself and also the Relationships of that Object (which are Objects themselves) and we pivot all this in a bunch of ways that allow you to browse, get statistics and build context around them.

For a basic example, in a process listing you may get the following:
- Object( 'iexplore.exe', PROCESS_NAME )
- Object( 'wininet.dll', MODULE_NAME )
- Relation( 'iexplore.exe', PROCESS_NAME, 'wininet.dll', MODULE_NAME )

And in a network-summary:
- Object( 'iexplore.exe', PROCESS_NAME )
- Object( '80', PORT )
- Relation( 'iexplore.exe', PROCESS_NAME, '80', PORT )