// Example code for node-snmp-native.
// ----

// This file contains examples of how to use the library.

// Basic setup
// -----

// The snmp object is the main entry point to the library.
var snmp = require('snmp-native');

var util = require('util');

var host = 'localhost';
var community = 'public';

// A session is required to communicate with an agent.
var session = new snmp.Session({ host: host, community: community });

// All OIDs are represented as integer arrays.
// There is no interpretation of string or MIB names.
// This here is the OID for sysDescr.0.
var oid = [1, 3, 6, 1, 2, 1, 1, 1, 0];

// Getting a single value
// -----

// This is how you issue a simple get request.
session.get({ oid: oid }, function (err, varbinds) {
    var vb;

    if (err) {
        // If there is an error, such as an SNMP timeout, we'll end up here.
        console.log(err);
    } else {
        vb = varbinds[0];
        console.log('The system description is "' + vb.value + '"');
    }

    // The session must be closed when you're done with it.
    session.close();
});

// Parsing an OID string and getting an entire tree
// -----

// Here we convert an OID from string representation to array.
// This is the base OID for the ifName tree.

var oidStr = '.1.3.6.1.2.1.31.1.1.1.1';
oid = oidStr
    .split('.')
    .filter(function (s) { return s.length > 0; })
    .map(function (s) { return parseInt(s, 10); });

// You can also get an entire subtree (an SNMP walk).

var session2 = new snmp.Session({ host: host, community: community });
session2.getSubtree({ oid: oid }, function (err, varbinds) {
    if (err) {
        // If there is an error, such as an SNMP timeout, we'll end up here.
        console.log(err);
    } else {
        // This is the list of varbinds.
        varbinds.forEach(function (vb) {
            console.log('Name of interface ' + vb.oid[vb.oid.length - 1]  + ' is "' + vb.value + '"');
        });
    }

    session2.close();
});

// You can get all of a collection of OIDs in one go.
// The semantics is similar to getSubtree.

var session3 = new snmp.Session({ host: host, community: community });
var oids = [[1, 3, 6, 1, 2, 1, 1, 1, 0], [1, 3, 6, 1, 2, 1, 1, 2, 0]];
session3.getAll({ oids: oids }, function (err, varbinds) {
    varbinds.forEach(function (vb) {
        console.log(vb.oid + ' = ' + vb.value);
    });
    session3.close();
});

// You can also create a destination-less "session" to use on multiple
// hosts. This is useful for conserving file descriptors when talking
// to a large number of hosts. This example scans the 192.168.1.0/24
// network for SNMP responders.

var session4 = new snmp.Session({ community: community }); // New session without host parameter. We set community to avoid repeating it later.
var oid = [1, 3, 6, 1, 2, 1, 1, 1, 0]; // sysDescr.0
var cnt = 254; // Expected number of callbacks.
for (var i = 1; i < 255; i++) {
    /*jshint loopfunc:true */
    // We need a function to get a closure over i.
    (function (host) {
        session4.get({ oid: oid, host: host }, function (err, vbs) {
            if (err) {
                // Probably a Timeout.
                console.log('Error for ' + host + ': ' + err);
            } else {
                // Print the returned value (sysDescr).
                var vb = vbs[0];
                console.log(host + ': ' + vb.oid + ' = ' + vb.value);
            }

            if (--cnt === 0) {
                // All requests have returned, time to close the session and exit.
                session4.close();
            }
        });
    }('192.168.1.' + i));
}

// Example output
// -----

// The expected output is something along these lines.
// Note that the asynchronicity results in the responses
// being printed in a different order that what you might
// guess from the above code.

/*
1,3,6,1,2,1,1,1,0 = Solaris anto.nym.se 11.0 physical
1,3,6,1,2,1,1,2,0 = 1,3,6,1,4,1,8072,3,2,3
The system description is "Solaris anto.nym.se 11.0 physical"
Name of interface 1 is "lo0"
Name of interface 2 is "e1000g0"
Name of interface 3 is "vboxnet0"
Name of interface 4 is "e1000g1"
Name of interface 5 is "he0"
Name of interface 6 is "nym0"
<... lots of timeouts for the scan stuff ...>
*/

