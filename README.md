node-snmp-native
================

This is (going to be) a native SNMP library for Node.js. The goal is to provide
enough functionality to perform basic monitoring of network equipment. This
includes:

 - Compatibility with SNMPv2c, including 64 bit data types.
 - Support for Get and GetNext requests.
 - No unusual external dependencies, no non-JS code.
 - High performance.

It specifically does **not** include:

 - Compatibility with SNMPv1, SNMPv2u or SNMPv3.
 - Support for Set requests.

Everything should naturally happen in a nice non-blocking, asynchronous manner.

Further features are up for discussion.

