var assert = require('assert');
var asn1ber = require('asn1ber');

describe('asn1ber', function () {
    describe('integer()', function () {
        it('returns one byte for zero', function () {
            var buf = asn1ber.integer(0);
            assert.equal(3, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(1, buf[1]); // Length
            assert.equal(0, buf[2]); // Value
        });
        it('returns one byte for one', function () {
            var buf = asn1ber.integer(1);
            assert.equal(3, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(1, buf[1]); // Length
            assert.equal(1, buf[2]); // Value
        });
        it('returns correctly for larger integer', function () {
            var buf = asn1ber.integer(1234567890);
            assert.equal(6, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(4, buf[1]); // Length
            assert.equal(73, buf[2]); // Value
            assert.equal(150, buf[3]); // Value
            assert.equal(2, buf[4]); // Value
            assert.equal(210, buf[5]); // Value
        });
    });

    describe('null()', function () {
        it('returns the null representation', function () {
            var buf = asn1ber.null();
            assert.equal(2, buf.length);
            assert.equal(5, buf[0]); // Null
            assert.equal(0, buf[1]); // Zero
        });
    });

    describe('sequence()', function () {
        it('returns an empty sequence', function () {
            var buf = asn1ber.sequence(new Buffer(0));
            assert.equal(2, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(0, buf[1]); // Zero length
        });
        it('returns wrapped sequence', function () {
            var buf = asn1ber.sequence(new Buffer(10));
            assert.equal(12, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(10, buf[1]); // Length
        });
        it('does not modify the passed data', function () {
            var orig = new Buffer(10);
            for (i = 0; i < 10; i++) {
                orig[i] = i;
            }

            var buf = asn1ber.sequence(orig);
            var i;
            assert.equal(12, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(10, buf[1]); // Length
            for (i = 0; i < 10; i++) {
                assert.equal(i, buf[i+2]);
            }
        });
    });

    describe('octetString()', function () {
        it('returns an empty string', function () {
            var buf = asn1ber.octetString('');
            assert.equal(2, buf.length);
            assert.equal(4, buf[0]); // OctetString
            assert.equal(0, buf[1]); // Zero length
        });
        it('returns a simple string correctly', function () {
            var str = 'abc';
            var buf = asn1ber.octetString(str);
            var i;
            assert.equal(5, buf.length);
            assert.equal(4, buf[0]); // OctetString
            assert.equal(str.length, buf[1]); // Length
            for (i = 0; i < str.length; i++) {
                assert.equal(str.charCodeAt(i), buf[i+2]);
            }
        });
    });

    describe('oid()', function () {
        it('throws an exception on empty OID', function (done) {
            try {
                asn1ber.oid([]);
            } catch (err) {
                assert.equal("Minimum OID length is two.", err.message);
                done();
            }
        });
        it('throws an exception for incorrect SNMP OIDs', function (done) {
            try {
                asn1ber.oid([1, 5, 6, 7, 8]);
            } catch (err) {
                assert.equal("SNMP OIDs always start with .1.3.", err.message);
                done();
            }
        });
        it('returns an oid correctly', function () {
            var oid = [1,3,6,1,4,1,2680,1,2,7,3,2,0];
            var correct = '06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00'.replace(/ /g, '');
            var buf = asn1ber.oid(oid);
            assert.equal(correct, buf.toString('hex'));
        });
    });

    describe('request()', function () {
        it('returns a get request sequence', function () {
            var buf = asn1ber.request(0, new Buffer(0));
            assert.equal(2, buf.length);
            assert.equal(160, buf[0]); // GetRequest
            assert.equal(0, buf[1]); // Zero length
        });
    });

    describe('parseInteger()', function () {
        it('throws an exception when passed a non-integer buffer', function (done) {
            try {
                var buf = new Buffer('040100', 'hex');
                asn1ber.parseInteger(buf);
            } catch (err) {
                done();
            };
        });
        it('returns zero for an encoded zero', function () {
            var buf = new Buffer('020100', 'hex');
            var int = asn1ber.parseInteger(buf);
            assert.equal(0, int);
        });
        it('returns one for an encoded one', function () {
            var buf = new Buffer('020101', 'hex');
            var int = asn1ber.parseInteger(buf);
            assert.equal(1, int);
        });
        it('correctly parses a random larger integer', function () {
            var buf = new Buffer('0204499602d2', 'hex');
            var int = asn1ber.parseInteger(buf);
            assert.equal(1234567890, int);
        });
    });

    describe('parseOctetString()', function () {
        it('throws an exception when passed a non-octetstring buffer', function (done) {
            try {
                var buf = new Buffer('020100', 'hex');
                asn1ber.parseOctetString(buf);
            } catch (err) {
                done();
            };
        });
        it('returns an empty string', function () {
            var buf = new Buffer('0400', 'hex');
            var str = asn1ber.parseOctetString(buf);
            assert.equal('', str);
        });
        it('correctly parses a random string', function () {
            var buf = new Buffer('0407536f6c61726973', 'hex');
            var str = asn1ber.parseOctetString(buf);
            assert.equal('Solaris', str);
        });
    });
});
