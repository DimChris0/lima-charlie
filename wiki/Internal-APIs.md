These APIs are available to Hunters and other Actors. This documentation is here to help you in the development of Hunters.

# Models
An ActorHandle is available to Hunters as *self.Models*.
This is a Beach API, so accessible via *self.Models.request( 'command', { 'key' : 'value' } )*
Here are the request types:

### get_timeline
Gets a raw list of events from a specific sensor between a start and end time.
* **id**: the sensor_id to lookup
* **max_size**: the maximum size an event can be to be returned, default 0
* **with_routing**: if True, include the routing information (sensor_id etc), default False
* **after**: second-based timestamp after which events are included in the timeline (inclusively), default None
* **before**: second-based timestamp before which events are included in the timeline (inclusively), default None
* **types**: a list of event types to include, default All
* **is_include_content**: include full event content if True, default False
Returns a *list[]* of *tuple( timeStamp, eventType, eventId )*, optional additional tuple value *eventContent{}* where *eventContent{}* is the raw event *dict{}* or a *dict{}* with *'routing{}'* and a *'event{}'*.

### get_obj_list
Gets a list of Objects matching parameters.
* **name**: an Object name which can contain '%' wildcards, default None
* **type**: an Object type, default None
* **host**: a sensor_id to restrict the search to, default None
* **orgs**: an org_id or list of org_id to restrict the search to, default None
Returns a *dict{}* with a *'objects[]'* where every element is a *tuple( id, objName, objType )*.

### get_obj_view
Gets detailed information about an object.
* **host**: a sensor_id to restrict the view of the Object from, default None
* **orgs**: an org_id or list of org_id to restrict the view of the Object from, default None
* **id**: an Object id to get the information about, default None
* **obj_name**: an Object name to get the information about, default None
* **obj_type**: an Object type that combined with the **obj_name** represents a single Object, default None

Must specify one of **id** or ( **obj_name** AND **obj_type** ). 
Returns a *dict{}* with:
* **id**
* **oname**
* **otype**
* **'olocs'[]** which is the list of sensor_id where the Object has been seen (as filtered by other parameters) where each location is a *tuple( sensor_id, timestamp )*
* **'parents'{}** and **'children'{}** containing Objects as a *list[]* with *tuple( id, obj_name, obj_type, obj_id_of_relation )*
* **'locs'** which is a *dict{}* of *id* as key and *count( global_locations )*
* **'rlocs'** which is a *dict{}* of *id* as key and *count( global_relation_locations )*

### get_lastevents
Gets a list of the last instance of every event received from a sensor.
* **id**: a sensor_id to get the last events from
Returns a *dict{}* with *'events'[]* where each event is a *tuple( event_name, event_id )*

### get_lastips
Gets the last internal and external IP address of a sensor.
* **id**: a sensor_id to get the IPs for
Returns a *dict{}* with an *external* and *internal* IP

### get_event

### list_sensors

### get_detects

### get_detect

### get_host_changes

### get_kv

### set_kv

### get_obj_loc

### get_file_in_event

### get_atoms_from_root

### get_backend_config

### get_installer

# Hunter

This is a native API in the Hunter superclass, so accessible via *self.command(...)* from a Hunter.

### getSingleAtom( atomId )
Get the event represented by an atom.

### getChildrenAtoms( atomId, depth = 5 )
Get all children events from a specific event/atom up to a depth.

### crawlUpParentTree( rootEvent, rootAtom = None )
A generator, that will keep generating events going from a root to each parent in the parent chain.

### getObjectInfo( objName, objType )
Get detailed Object information about a specific Object.

### getLastNSecondsOfEventsFrom( lastNSeconds, host, ofTypes = None )
Get the list of events from a specific sensor (and optionally specific type) from the last N seconds.

### getEventsNSecondsAround( nSeconds, aroundTime, host, ofTypes = None )
Get the list of events from a specific sensor (and optionally specific type) for N seconds around a specific second-based timestamp.

### getVTReport( fileHash )
Get the VT report about a specific file hash.

### isAlexaDomain( domainName )
Check if a specific domain is in the Alexa top 100000, returned as a bool.