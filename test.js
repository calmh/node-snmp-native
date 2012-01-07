var snmp = require('snmp');

var pkt = new snmp.Packet();
pkt.community = 'nym.se';
pkt.pdu.varbinds[0].oid = [1, 3, 6, 1, 2, 1, 1, 1, 0];
console.dir(pkt);
var req = snmp.ber(pkt);
var dgram = require('dgram');
var client = dgram.createSocket('udp4');
client.send(req, 0, req.length, 161, 'anto.nym.se', function (err, bytes) {
    console.log(err);
    console.log(bytes);
    client.close();
});

