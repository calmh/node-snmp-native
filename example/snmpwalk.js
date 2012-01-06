#!/usr/bin/env node

var _ = require('underscore');
var snmp = require('snmp');

if (process.argv.length < 4) {
    console.log("Usage:");
    console.log("  " + process.argv[1] + " [host] [community] [oid]");
} else {
    var sess, oid, prevOid;

    function walker(err, pkt) {
        var oidStr;

        if (err) {
            console.log(err);
            sess.close();
        } else {
            if (pkt.pdu.varbinds[0].value == 'endOfMibView') {
                console.log("Done!");
                sess.close();
                return;
            } else if (snmp.compareOids(prevOid, pkt.pdu.varbinds[0].oid) == 1) {
                oidStr = '.' + pkt.pdu.varbinds[0].oid.join('.');
                console.log(oidStr + ' = ' + pkt.pdu.varbinds[0].value);
                prevOid = pkt.pdu.varbinds[0].oid;
                sess.getNext(pkt.pdu.varbinds[0].oid, walker);
            } else {
                console.log(prevOid + ' >= ' + pkt.pdu.varbinds[0].oid);
                sess.close();
            }
        }
    }

    sess = new snmp.Session(process.argv[2], process.argv[3]);
    oid = process.argv[4] || '.1.3.6.1.2.1';
    oid = _.map(_.compact(oid.split('.')), function (s) { return parseInt(s, 10); });
    sess.getNext(oid, walker);
}

