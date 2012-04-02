node-snmp-native
================

This is a native SNMP library for Node.js. The goal is to provide
enough functionality to perform basic monitoring of network equipment. This
includes:

 - Compatibility with SNMPv2c, including 64 bit data types.
 - Support for Get and GetNext requests.
 - No unusual external dependencies, no non-JS code.
 - High performance.

It specifically does **not** include:

 - Compatibility with SNMPv1, SNMPv2u or SNMPv3.
 - MIB parsing.

Everything should naturally happen in a nice non-blocking, asynchronous manner.

Installation
------------

    npm install snmp-native

Usage
-----

### Import

    var snmp = require('snmp-native');

### new Session(options)

Create a `Session`. The `Session` constructor, like most of the other
functions, take an `options` object. The options passed to the `Session` will
be the defaults for any subsequent function calls on that session, but can be
overridden as needed. Useful parameters here are `host`, `port` and `family`.

    # Create a Session with default settings.
    var session = new snmp.Session();

    # Create a Session with explicit default host, port, and community.
    var session = new snmp.Session({ host: 'device.example.com', port: 161, community: 'special' });

    # Create an IPv6 Session.
    var session = new snmp.Session({ host: '2001:db8::42', family: 'udp6', community: 'private' });

The following options are recognized as properties in the options object. All
can be specified in the `Session` constructor and optionally overridden at a
later time by setting them in the option object to a method call.

 - *host*: The host to send the request to. An resolvable name is allowed in
   addition to IP addresses. Default: `'localhost'`.
 - *port*: The UDP port number to send the request to. Default: `161`.
 - *community*: The SNMP community name. Default: `'public'`.
 - *family*: Address family to bind to. This is only used by the `Session`
   constructor since that is when the bind is done. It cannot be changed or
   overridden after construction. Default: `'udp4'`. Valid values: `'udp4'` or
   `'udp6'`.
 - *timeouts*: An array of timeout values. Values are times in milliseconds,
   the length of the array is the total number of transmissions that will
   occur. Default: `[5000, 5000, 5000, 5000]` (four attempts, with five seconds
   between each). A backoff can be implemented by timeouts along the lines of
   `[ 1000, 2000, 4000, 8000 ]`. Retransmissions can be disabled by using only
   a single timeout value: `[ 5000 ]`.

### get(options, callback)

Perform a simple GetRequest. Options (in addition to the ones defined above for `Session`):

 - *oid*: The OID to get. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]` or `'.1.3.6.1.4.1.1.2.3.4'`.
 
Will call the specified `callback` with an `error` object (`null` on success) and the varbind that was received.

    session.get({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0] }, function (error, varbind) {
        if (error) {
            console.log('Fail :(');
        } else {
            console.log(varbind.oid + ' = ' + varbind.value + ' (' + varbind.type + ')');
        }
    });

You can also specify host, community, etc explicitly.

    session.get({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0], host: 'localhost', community: 'test' }, ...);

### getNext(options, callback)

Perform a simple GetNextRequest. Options:

 - *oid*: The OID to get. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]` or `'.1.3.6.1.4.1.1.2.3.4'`.

Will call the specified `callback` with an `error` object (`null` on success)
and the varbind that was received.

    session.getNext({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0] }, function (error, varbind) {
        if (error) {
            console.log('Fail :(');
        } else {
            console.log(varbind.oid + ' = ' + varbind.value + ' (' + varbind.type + ')');
        }
    });

### getAll(options, callback)

Perform repeated GetRequests to fetch all the required values. Options:

 - *oids*: An array of OIDs to get. Example: `[[1, 3, 6, 1, 4, 1, 1, 2, 3], [1, 3, 6, 1, 4, 1, 1, 2, 4]]` or `['.1.3.6.1.4.1.1.2.3.4', '.1.3.6.1.4.1.2.3.4.5']`.
 - *abortOnError*: Whether to stop or continue when an error is encountered. Default: `false`. 

The callback will be called with an error object or a list of varbinds. If the
options property `abortOnError` is false (default) any variables that couldn't
be fetched will simply be omitted from the results. If it is true, the callback
will be called with an error object on any failure.

    var oids = [ [1, 3, 6, 1, 4, 1, 42, 1, 0], [1, 3, 6, 1, 4, 1, 42, 2, 0], ... ];
    session.getAll({ oids: oids }, function (error, varbinds) {
        varbinds.forEach(function (vb) {
            console.log(vb.oid + ' = ' + vb.value + ' (' + vb.type + ')');
        });
    });

### getSubtree(options, callback)

Perform repeated GetNextRequests to fetch all values in the specified tree. Options:

 - *oid*: The OID to get. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]` or `'.1.3.6.1.4.1.1.2.3.4'`.

Will call the specified `callback` with an `error` object (`null` on success)
and the list of varbinds that was fetched.

    session.getSubtree({ oid: [1, 3, 6, 1, 4, 1, 42] }, function (error, varbinds) {
        if (error) {
            console.log('Fail :(');
        } else {
            varbinds.forEach(function (vb) {
                console.log(vb.oid + ' = ' + vb.value + ' (' + vb.type + ')');
            });
        }
    });

### set(options, callback)

Perform a simple SetRequest. Options:

 - *oid*: The OID to perform the set on. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]` or `'.1.3.6.1.4.1.1.2.3.4'`.
 - *value*: The value to set. Example: `42`
 - *type*: The type of the value. Currently only `asn1ber.T.Integer` (2) is allowed. Example: `2`

Example:

    session.set({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0], value: 42, type: 2 }, function (error, varbind) {
        if (error) {
            console.log('Fail :(');
        } else {
            console.log('The set is done.');
        }
    });

