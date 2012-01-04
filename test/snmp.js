var assert = require('assert');
var snmp = require('snmp');

describe('snmp', function () {
    describe('ber()', function () {
        it('returns a correctly formatted buffer from a default packet description', function () {
            var correct = '30 2c 02 01 01 04 07 70 72 69 76 61 74 65 a0 1e 02 01 01 02 01 00 02 01 00 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, '');
            var pkt = new snmp.Packet(); // A default getrequest
            pkt.community = 'private';
            pkt.pdu.varbinds[0].oid = [1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 2, 0];
            var msg = snmp.ber(pkt);
            assert.equal(msg.toString('hex'), correct);
        });
    });
});

