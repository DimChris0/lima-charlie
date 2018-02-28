# Meta Headers

All communications in LC are based on the `rpcm` library, which is available in C and Python. Think of it as a freeform version of `protobuf` where elements have a tag, a type and a value (like JSON + types) and can be formed and embedded within each other without the requirement for a pre-defined message format like `protobuf`.

When adding new features to LC, you may need to add new tags. If that's the case, you will want to add them to the `/meta_headers/rp_hcp_tags.json` file. As you will see in the file, different sections are defined. If the tag can make sense in a different context, add it to the `base` section, if not, you may want to add it to the `hbs` section, or to the `notification` section if the tag is an event type.

Once you've added the tags to the .json file, call `/tools/update_headers.py`. This last script will take the
tag definition you've added and will generate the various C and JSON headers for the other components of the system.