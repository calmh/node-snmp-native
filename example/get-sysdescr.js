#!/usr/bin/env node

var snmp = require('snmp');

if (process.argv.length < 4) {
    console.log("Usage:");
    console.log("  " + process.argv[1] + " [host] [community]");
} else {
    var sess = new snmp.Session(process.argv[2], process.argv[3]);
    sess.get([1, 3, 6, 1, 2, 1, 1, 1, 0], function (err, pkt) {
        if (err) {
            console.log(err);
        } else {
            console.log(pkt.pdu.varbinds[0].value);
        }
        sess.close();
    });
}

