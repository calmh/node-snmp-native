var assert = require('assert');
var snmp = require('snmp');

describe('snmp', function () {
    describe('encode()', function () {
        it('returns a correctly formatted buffer from a packet description', function () {
            var correct = '30 2c 02 01 01 04 07 70 72 69 76 61 74 65 a0 1e 02 01 05 02 01 06 02 01 07 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, '');
            var pkt = new snmp.Packet(); // A default getrequest
            pkt.community = 'private';
            pkt.pdu.reqid = 5;
            pkt.pdu.error = 6;
            pkt.pdu.errorIndex = 7;
            pkt.pdu.varbinds[0].oid = [1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 2, 0];
            var msg = snmp.encode(pkt);
            assert.equal(msg.toString('hex'), correct);
        });
    });

    describe('parse()', function () {
        it('returns a snmp.Packet structure', function () {
            var ex = new Buffer('30 2c 02 01 01 04 07 70 72 69 76 61 74 65 a0 1e 02 01 01 02 01 00 02 01 00 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, ''), 'hex');
            var pkt = snmp.parse(ex);
            assert.equal('Packet', pkt.constructor.name);
        });
        it('returns a correct SNMP version field', function () {
            var ex = new Buffer('30 2c 02 01 47 04 07 70 72 69 76 61 74 65 a0 1e 02 01 01 02 01 00 02 01 00 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, ''), 'hex');
            var pkt = snmp.parse(ex);
            assert.equal(0x47, pkt.version);
        });
        it('returns a correct SNMP community field', function () {
            var ex = new Buffer('30 2c 02 01 47 04 07 70 72 69 76 61 74 65 a0 1e 02 01 01 02 01 00 02 01 00 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, ''), 'hex');
            var pkt = snmp.parse(ex);
            assert.equal('private', pkt.community);
        });
        it('returns a correct pdu type field', function () {
            var ex = new Buffer('30 2c 02 01 47 04 07 70 72 69 76 61 74 65 a4 1e 02 01 01 02 01 00 02 01 00 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, ''), 'hex');
            var pkt = snmp.parse(ex);
            assert.equal(4, pkt.pdu.type);
        });
        it('returns a correct request id field', function () {
            var ex = new Buffer('30 2c 02 01 47 04 07 70 72 69 76 61 74 65 a4 1e 02 01 33 02 01 00 02 01 00 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, ''), 'hex');
            var pkt = snmp.parse(ex);
            assert.equal(0x33, pkt.pdu.reqid);
        });
        it('returns a correct error field', function () {
            var ex = new Buffer('30 2c 02 01 47 04 07 70 72 69 76 61 74 65 a4 1e 02 01 33 02 01 44 02 01 00 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, ''), 'hex');
            var pkt = snmp.parse(ex);
            assert.equal(0x44, pkt.pdu.error);
        });
        it('returns a correct error index field', function () {
            var ex = new Buffer('30 2c 02 01 47 04 07 70 72 69 76 61 74 65 a4 1e 02 01 33 02 01 00 02 01 55 30 13 30 11 06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00 05 00'.replace(/ /g, ''), 'hex');
            var pkt = snmp.parse(ex);
            assert.equal(0x55, pkt.pdu.errorIndex);
        });
    });
});

