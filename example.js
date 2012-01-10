/*jslint onevar: true, node: true, continue: false, plusplus: false, bitwise: true, plusplus: true
  newcap: true, strict: false, maxerr: 50, indent: 4, undef: true, sloppy: true, nomen: true*/

// Example code for node-snmp-native.
// ----

// This file contains examples of how to use the library.

// Basic setup
// -----

// The snmp object is the main entry point to the library.
var snmp = require('snmp-native');

// We'll use the Underscore library for a few convenience functions.
// You should too. We'll also pull in the `util` library so we can print
// out object structures nicely.
var _ = require('underscore');
var util = require('util');

var host = 'localhost';
var community = 'public';

// A session is required to communicate with an agent.
var session = new snmp.Session(host, community);

// All OIDs are represented as integer arrays.
// There is no interpretation of string or MIB names.
// This here is the OID for sysDescr.0.
var oid = [1, 3, 6, 1, 2, 1, 1, 1, 0];

// Getting a single value
// -----

// This is how you issue a simple get request.
session.get(oid, function (err, pkt) {
    var vb;

    if (err) {
        // If there is an error, such as an SNMP timeout, we'll end up here.
        console.log(err);
    } else {
        // The pkt parameter is a Packet instance, which is closely
        // modelled after the actual layout of an SNMP packet.
        // The minimum you need to know is that there is an array of varbinds
        // that usually contain exactly one entry, in which the 'value'
        // property holds the reply.
        vb = pkt.pdu.varbinds[0];
        console.log('The system description is "' + vb.value + '"');

        // For reference, this shows how the entire structure looks.
        console.log('\nThe received Packet structure looks like this:');
        console.log(util.inspect(pkt, false, null) + '\n');
    }

    // The session must be closed when you're done with it.
    session.close();
});

// Parsing an OID string and getting an entire tree
// -----

// We'll establish a new session since we're doing something independently of the previous requests.
// Since it's all asynchronous, it's likely that we haven't received the response and closed the session
// above yet, but it might happen later while we're doing other stuff.
var session2 = new snmp.Session(host, community);

// Here we convert an OID from string representation to array.
// This is the base OID for the ifName tree.
var oidStr = '.1.3.6.1.2.1.31.1.1.1.1';
oid = _.map(_.compact(oidStr.split('.')), function (x) { return parseInt(x, 10); });

// You can also get an entire subtree (an SNMP walk).
session2.getSubtree(oid, function (err, pkt) {
    var vb;

    // The callback will be called once for each entry in the tree.

    if (err) {
        // If there is an error, such as an SNMP timeout, we'll end up here.
        console.log(err);
    } else if (pkt === null) {
        // A null pkt without an error means that we're at the end of tree.
        // Close the session since we're done.
        session2.close();
    } else {
        vb = pkt.pdu.varbinds[0];
        console.log('Name of interface ' + _.last(vb.oid)  + ' is "' + vb.value + '"');
    }
});

// Example output
// -----

// The expected output is something along these lines.
// Note that the asynchronicity results in a response to the getSubtree
// being printed before the system description.

/*
jb@apto:~/superpoller % node example.js
Name of interface 1 is "lo0"
The system description is "Solaris anto.nym.se 11.0 physical"

The received Packet structure looks like this:
{ version: 1,
  community: 'public',
  pdu: 
   { type: 2,
     reqid: 1353455559,
     error: 0,
     errorIndex: 0,
     varbinds: 
      [ { type: 4,
          value: 'Solaris anto.nym.se 11.0 physical',
          oid: [ 1, 3, 6, 1, 2, 1, 1, 1, 0 ] } ] } }

Name of interface 2 is "e1000g0"
Name of interface 3 is "vboxnet0"
Name of interface 4 is "he0"
*/

