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
 - Support for Set requests. Even though this is easy, it's seldom recommended.
 - MIB parsing.

Everything should naturally happen in a nice non-blocking, asynchronous manner.

Currently, the interface (which might evolve suddenly while the project is in
0.x version territory) looks like this:

    // The snmp object is the main entry point to the library.
    var snmp = require('snmp-native');
    
    // A session is required to communicate with an agent.
    var session = new snmp.Session('127.0.0.1', 'public');
    
    // All OIDs are represented as integer arrays.
    var oid = [1, 3, 6, 1, 2, 1, 1, 1, 0];
    
    session.get(oid, function (err, pkt) {
        if (err) {
            console.log(err);
        } else {
            // The pkt parameter is a Packet instance, which is closely
            // modelled after the actual layout of an SNMP packet.
            // The least you need to know is that there is an array of varbinds
            // that usually contain exactly one entry, in which the 'value'
            // property holds the reply.
            console.log(pkt.pdu.varbinds[0].value);
        }
    
        // The session must be closed when you're done with it.
        session.close();
    });

There are further usage examples in the `example` directory.

To install:

    npm install snmp-native

You can also view the annotated source code at http://nym.se/node-snmp-native/docs/

-- 
Jakob Borg
jakob@nym.se
