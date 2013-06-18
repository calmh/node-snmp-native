                                                                 __
                                                                /\ \__  __
      ____    ___     ___ ___   _____              ___      __  \ \ ,_\/\_\   __  __     __
     /',__\ /' _ `\ /' __` __`\/\ '__`\  _______ /' _ `\  /'__`\ \ \ \/\/\ \ /\ \/\ \  /'__`\
    /\__, `\/\ \/\ \/\ \/\ \/\ \ \ \L\ \/\______\/\ \/\ \/\ \L\.\_\ \ \_\ \ \\ \ \_/ |/\  __/
    \/\____/\ \_\ \_\ \_\ \_\ \_\ \ ,__/\/______/\ \_\ \_\ \__/.\_\\ \__\\ \_\\ \___/ \ \____\
     \/___/  \/_/\/_/\/_/\/_/\/_/\ \ \/           \/_/\/_/\/__/\/_/ \/__/ \/_/ \/__/   \/____/
                                  \ \_\
                                   \/_/

snmp-native  [![Build Status](https://secure.travis-ci.org/calmh/node-snmp-native.png)](http://travis-ci.org/calmh/node-snmp-native)
===========

This is a native SNMP library for Node.js. The purpose is to provide enough
functionality to perform large scale monitoring of network equipment. Current
features towards this end are:

 - Full implementation of SNMPv2c, including 64 bit data types.
 - Support for Get, GetNext and Set requests, with optimizations such as GetAll
   and GetSubtree.
 - No unusual external dependencies, no non-JavaScript code.
 - Very high performance, unlimited parallellism. (There are always limits.
   However, there are no arbitrary such imposed by this code and you at least
   won't run out of file descriptors.)
 - De facto standards compliance. Generated packets are compared against
   Net-SNMP and should be identical in all relevant aspects.
 - Well tested. Test coverage should be at or close to 100% for all important
   code paths.

It specifically does *not* include:

 - Compatibility with SNMPv1, SNMPv2u or SNMPv3. These are (in order)
   deprecated, weird, and too complicated. Yes, it's an opinionated library.
 - MIB parsing. Do this in your client app if it's necessary.

It's optimized for polling tens of thousands of counters on hundreds or
thousands of hosts in a parallell manner. This is known to work (although
performance might be limited by less than optimal SNMP agent implementations in
random network gear).

Documentation
=============

See API documentation below, the [annotated source code](http://nym.se/node-snmp-native/docs/snmp.html)
and an [example](http://nym.se/node-snmp-native/docs/example.html) to get started.

Installation
------------

    $ npm install snmp-native

Usage
-----

### Import

```javascript
var snmp = require('snmp-native');
```

### new Session(options)

Create a `Session`. The `Session` constructor, like most of the other
functions, take an `options` object. The options passed to the `Session` will
be the defaults for any subsequent function calls on that session, but can be
overridden as needed. Useful parameters here are `host`, `port` and `family`.

```javascript
// Create a Session with default settings.
var session = new snmp.Session();

// Create a Session with explicit default host, port, and community.
var session = new snmp.Session({ host: 'device.example.com', port: 161, community: 'special' });

// Create an IPv6 Session.
var session = new snmp.Session({ host: '2001:db8::42', family: 'udp6', community: 'private' });
```

The following options are recognized as properties in the options object. All
can be specified in the `Session` constructor and optionally overridden at a
later time by setting them in the option object to a method call.

For optimum performance when polling many hosts, create a session without
specifying the `host`. Reuse this session for all hosts and specify the `host`
on each `get`, `getAll`, etc.

 - `host`: The host to send the request to. An resolvable name is allowed in
   addition to IP addresses. Default: `'localhost'`.
 - `port`: The UDP port number to send the request to. Default: `161`.
 - `community`: The SNMP community name. Default: `'public'`.
 - `family`: Address family to bind to. This is only used by the `Session`
   constructor since that is when the bind is done. It cannot be changed or
   overridden after construction. Default: `'udp4'`. Valid values: `'udp4'` or
   `'udp6'`.
 - `timeouts`: An array of timeout values. Values are times in milliseconds,
   the length of the array is the total number of transmissions that will
   occur. Default: `[5000, 5000, 5000, 5000]` (four attempts, with five seconds
   between each). A backoff can be implemented by timeouts along the lines of
   `[ 1000, 2000, 4000, 8000 ]`. Retransmissions can be disabled by using only
   a single timeout value: `[ 5000 ]`.

### VarBind objects

All of the `get*` functions return arrays of `VarBind` as the result to the
callback. The `VarBind` objects have the following properties:

 - `oid`: The OID they represent (in array form).
 - `type`: The integer type code for the returned value.
 - `value`: The value, in decoded form. This will be an integer for integer,
   gauge, counter and timetick types, a string for an octet string value, an
   array for array or IP number types.
 - `valueRaw`: For octet string values, this is a raw `Buffer` representing the string.
 - `valueHex`: For octet string values, this is a hex string representation of the value.
 - `sendStamp`: The timestamp (in milliseconds) when the request was transmitted.
 - `receiveStamp`: The timestamp (in milliseconds) when the response was received.

### get(options, callback)

Perform a simple GetRequest. Options (in addition to the ones defined above for `Session`):

 - `oid`: The OID to get. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]` or
   `'.1.3.6.1.4.1.1.2.3.4'`. Both forms are accepted, but the string form will
   need to be parsed to an array, slightly increasing CPU usage.
 
Will call the specified `callback` with an `error` object (`null` on success)
and the varbind that was received.

```javascript
session.get({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0] }, function (error, varbinds) {
    if (error) {
        console.log('Fail :(');
    } else {
        console.log(varbinds[0].oid + ' = ' + varbinds[0].value + ' (' + varbinds[0].type + ')');
    }
});
```

You can also specify host, community, etc explicitly.

```javascript
session.get({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0], host: 'localhost', community: 'test' }, ...);
```

### getNext(options, callback)

Perform a simple GetNextRequest. Options:

 - `oid`: The OID to get. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]` or `'.1.3.6.1.4.1.1.2.3.4'`.

Will call the specified `callback` with an `error` object (`null` on success)
and the varbind that was received.

```javascript
session.getNext({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0] }, function (error, varbinds) {
    if (error) {
        console.log('Fail :(');
    } else {
        console.log(varbinds[0].oid + ' = ' + varbinds[0].value + ' (' + varbinds[0].type + ')');
    }
});
```

### getAll(options, callback)

Perform repeated GetRequests to fetch all the required values. Multiple OIDs
will get packed into as few GetRequest packets as possible to minimize
roundtrip delays. Gets will be issued serially (not in parallell) to avoid
flooding hosts. Options:

 - `oids`: An array of OIDs to get. Example: `[[1, 3, 6, 1, 4, 1, 1, 2, 3], [1,
   3, 6, 1, 4, 1, 1, 2, 4]]` or `['.1.3.6.1.4.1.1.2.3.4',
   '.1.3.6.1.4.1.2.3.4.5']`.
 - `abortOnError`: Whether to stop or continue when an error is encountered.
   Default: `false`.

The callback will be called with an error object or a list of varbinds. If the
options property `abortOnError` is false (default) any variables that couldn't
be fetched will simply be omitted from the results. If it is true, the callback
will be called with an error object on any failure.

```javascript
var oids = [ [1, 3, 6, 1, 4, 1, 42, 1, 0], [1, 3, 6, 1, 4, 1, 42, 2, 0], ... ];
session.getAll({ oids: oids }, function (error, varbinds) {
    varbinds.forEach(function (vb) {
        console.log(vb.oid + ' = ' + vb.value + ' (' + vb.type + ')');
    });
});
```

### getSubtree(options, callback)

Perform repeated GetNextRequests to fetch all values in the specified tree. Options:

 - `oid`: The OID to get. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]` or `'.1.3.6.1.4.1.1.2.3.4'`.

Will call the specified `callback` with an `error` object (`null` on success)
and the list of varbinds that was fetched.

```javascript
session.getSubtree({ oid: [1, 3, 6, 1, 4, 1, 42] }, function (error, varbinds) {
    if (error) {
        console.log('Fail :(');
    } else {
        varbinds.forEach(function (vb) {
            console.log(vb.oid + ' = ' + vb.value + ' (' + vb.type + ')');
        });
    }
});
```

### set(options, callback)

Perform a simple SetRequest. Options:

 - `oid`: The OID to perform the set on. Example: `[1, 3, 6, 1, 4, 1, 1, 2, 3, 4]`
   or `'.1.3.6.1.4.1.1.2.3.4'`.
 - `value`: The value to set. Example: `42`.
 - `type`: The type of the value. Currently supports `asn1ber.T.Integer` (2), `asn1ber.T.Gauge` (66), 
   `asn1ber.T.IpAddress` (64), `asn1ber.T.OctetString` (4) and `asn1ber.T.Null` (5).
   Example: `2`.

Example:

```javascript
session.set({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0], value: 42, type: 2 }, function (error, varbind) {
    if (error) {
        console.log('Fail :(');
    } else {
        console.log('The set is done.');
    }
});
```

If you're not really interested in the outcome of the set (and if you are, why
aren't you using scripted telnet or ssh instead to begin with?), you can call
it without a callback:

```javascript
session.set({ oid: [1, 3, 6, 1, 4, 1, 42, 1, 0], value: 42, type: 2 });
```

License
=======

MIT

