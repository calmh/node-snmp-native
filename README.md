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

To install:

    npm install snmp-native

For usage, see http://nym.se/node-snmp-native/docs/example.html

There are further usage examples in the `example` directory.

You can also view the annotated source code at http://nym.se/node-snmp-native/docs/

-- 
Jakob Borg
jakob@nym.se
