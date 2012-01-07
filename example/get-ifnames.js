#!/usr/bin/env node

var _ = require('underscore');
var snmp = require('../lib/snmp');

if (process.argv.length < 4) {
    console.log("Usage:");
    console.log("  " + process.argv[1] + " [host] [community]");
} else {
    var sess, oid, prevOid;

    sess = new snmp.Session(process.argv[2], process.argv[3]);
    oid = '.1.3.6.1.2.1.31.1.1.1.1';
    oid = _.map(_.compact(oid.split('.')), function (s) { return parseInt(s, 10); });
    sess.getSubtree(oid, function (err, pkt) {
        var oidStr;

        if (err) {
            console.error(err);
        } else if (!pkt) {
            // We're done.
            sess.close();
        } else {
            oidStr = '.' + pkt.pdu.varbinds[0].oid.join('.');
            console.log(oidStr + ' = ' + pkt.pdu.varbinds[0].value);
        }
    });
}

