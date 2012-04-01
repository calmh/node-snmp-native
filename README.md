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

Default `options` if not specified:

    {
        host: 'localhost',
        port: 161,
        community: 'public',
        family: 'udp4'
    }

### get(options, callback)

Perform a simple GetRequest.

`get` takes an option object that needs at least the `oid` property set. Other
properties are inherited from the `Session` defaults if missing. Will call the
specified `callback` with an `error` object (`null` on success) and the varbind
that was received.

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

Perform a simple GetNextRequest.

`getNext` takes an option object that needs at least the `oid` property set. Other
properties are inherited from the `Session` defaults if missing. Will call the
specified `callback` with an `error` object (`null` on success) and the varbind
that was received.

    session.getNext({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0] }, function (error, varbind) {
        if (error) {
            console.log('Fail :(');
        } else {
            console.log(varbind.oid + ' = ' + varbind.value + ' (' + varbind.type + ')');
        }
    });

### getAll(options, callback)

Perform repeated GetRequests to fetch all the required values.

`getAll` acts like `get`, except the options object needs a property `oids`
that is an array of OIDs in array form. The callback will be called with an
error object and a list of varbinds. If the options property `abortOnError` is
false (default) any variables that couldn't be fetched will simply be omitted
from the results. If it is true, the callback will be called with an error
object on any failure.

    var oids = [ [1, 3, 6, 1, 4, 1, 42, 1, 0], [1, 3, 6, 1, 4, 1, 42, 2, 0], ... ];
    session.getAll({ oids: oids }, function (error, varbinds) {
        varbinds.forEach(function (vb) {
            console.log(vb.oid + ' = ' + vb.value + ' (' + vb.type + ')');
        });
    });

### getSubtree(options, callback)

Perform repeated GetNextRequests to fetch all values in the specified tree.

`getSubtree` takes an option object that needs at least the `oid` property set. Other
properties are inherited from the `Session` defaults if missing. Will call the
specified `callback` with an `error` object (`null` on success) and the varbind
that was received.

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

Perform a simple SetRequest.

`set` is like `get`, except it needs to additional properties: `value` which is the
integer value to set, and `type` which is the type of the value. Currently the only
supported value is `asn1ber.T.Integer` (2).

    session.set({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0], value: 42, type: 2 }, function (error, varbind) {
        if (error) {
            console.log('Fail :(');
        } else {
            console.log('The set is done.');
        }
    });

