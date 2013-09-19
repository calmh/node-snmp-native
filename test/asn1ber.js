var assert = require('assert');
var asn1ber = require('asn1ber');

describe('asn1ber', function () {
    describe('encodeInteger()', function () {
        it('returns one byte for zero', function () {
            var correct = '020100';
            var buf = asn1ber.encodeInteger(0);
            assert.equal(correct, buf.toString('hex'));
        });
        it('returns one byte for one', function () {
            var buf = asn1ber.encodeInteger(1);
            assert.equal(3, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(1, buf[1]); // Length
            assert.equal(1, buf[2]); // Value
        });
        it('does not return first byte and first bit of second byte all ones', function () {
            var correct = '020300ff94';
            var buf = asn1ber.encodeInteger(0xff94);
            assert.equal(correct, buf.toString('hex'));
        });
        it('does not return a negative-looking integer', function () {
            var correct = '02020088';
            var buf = asn1ber.encodeInteger(0x88);
            assert.equal(correct, buf.toString('hex'));
        });
        it('returns correctly for larger integer', function () {
            var buf = asn1ber.encodeInteger(1234567890);
            assert.equal(6, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(4, buf[1]); // Length
            assert.equal(73, buf[2]); // Value
            assert.equal(150, buf[3]); // Value
            assert.equal(2, buf[4]); // Value
            assert.equal(210, buf[5]); // Value
        });
        it('encodes a negative integer', function () {
            assert.equal('0201fe', asn1ber.encodeInteger(-2).toString('hex'));
            assert.equal('0202fdda', asn1ber.encodeInteger(-550).toString('hex'));
            assert.equal('0203ed2979', asn1ber.encodeInteger(-1234567).toString('hex'));
            assert.equal('0204f8a432eb', asn1ber.encodeInteger(-123456789).toString('hex'));
        });
    });

    describe('encodeGauge()', function () {
        it('returns one byte for zero', function () {
            var correct = '420100';
            var buf = asn1ber.encodeGauge(0);
            assert.equal(correct, buf.toString('hex'));
        });
        it('returns one byte for one', function () {
            var buf = asn1ber.encodeGauge(1);
            assert.equal(3, buf.length);
            assert.equal(0x42, buf[0]); // Gauge
            assert.equal(1, buf[1]); // Length
            assert.equal(1, buf[2]); // Value
        });
        it('does not return first byte and first bit of second byte all ones', function () {
            var correct = '420300ff94';
            var buf = asn1ber.encodeGauge(0xff94);
            assert.equal(correct, buf.toString('hex'));
        });
        it('does not return a negative-looking integer', function () {
            var correct = '42020088';
            var buf = asn1ber.encodeGauge(0x88);
            assert.equal(correct, buf.toString('hex'));
        });
        it('returns correctly for larger integer', function () {
            var buf = asn1ber.encodeGauge(1234567890);
            assert.equal(6, buf.length);
            assert.equal(0x42, buf[0]); // Gauge
            assert.equal(4, buf[1]); // Length
            assert.equal(73, buf[2]); // Value
            assert.equal(150, buf[3]); // Value
            assert.equal(2, buf[4]); // Value
            assert.equal(210, buf[5]); // Value
        });
    });

    describe('encodeNull()', function () {
        it('returns the null representation', function () {
            var buf = asn1ber.encodeNull();
            assert.equal(2, buf.length);
            assert.equal(5, buf[0]); // Null
            assert.equal(0, buf[1]); // Zero
        });
    });

    describe('encodeSequence()', function () {
        it('returns an empty sequence', function () {
            var buf = asn1ber.encodeSequence(new Buffer(0));
            assert.equal(2, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(0, buf[1]); // Zero length
        });
        it('returns wrapped sequence', function () {
            var buf = asn1ber.encodeSequence(new Buffer(10));
            assert.equal(12, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(10, buf[1]); // Length
        });
        it('returns correctly wrapped long sequence', function () {
            var buf = asn1ber.encodeSequence(new Buffer(1024));
            assert.equal(1024 + 1 + 3, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(128 + 2, buf[1]); // Length
            assert.equal(0x04, buf[2]); // Length
            assert.equal(0x00, buf[3]); // Length
        });
        it('does not modify the passed data', function () {
            var orig = new Buffer(10);
            for (i = 0; i < 10; i++) {
                orig[i] = i;
            }

            var buf = asn1ber.encodeSequence(orig);
            var i;
            assert.equal(12, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(10, buf[1]); // Length
            for (i = 0; i < 10; i++) {
                assert.equal(i, buf[i + 2]);
            }
        });
    });

    describe('encodeOctetString()', function () {
        it('returns an empty string', function () {
            var buf = asn1ber.encodeOctetString('');
            assert.equal(2, buf.length);
            assert.equal(4, buf[0]); // OctetString
            assert.equal(0, buf[1]); // Zero length
        });
        it('returns a simple string correctly', function () {
            var str = 'abc';
            var buf = asn1ber.encodeOctetString(str);
            var i;
            assert.equal(5, buf.length);
            assert.equal(4, buf[0]); // OctetString
            assert.equal(str.length, buf[1]); // Length
            for (i = 0; i < str.length; i++) {
                assert.equal(str.charCodeAt(i), buf[i + 2]);
            }
        });
        it('returns a simple buffer correctly', function () {
            var orig = new Buffer('0123456789', 'hex');
            var buf = asn1ber.encodeOctetString(orig);
            var i;
            assert.equal(7, buf.length);
            assert.equal(4, buf[0]); // OctetString
            assert.equal(orig.length, buf[1]); // Length
            for (i = 0; i < orig.length; i++) {
                assert.equal(orig[i], buf[i + 2]);
            }
        });
        it('throws an exception for unknown source types', function (done) {
            try {
                asn1ber.encodeOctetString(12);
            } catch (err) {
                done();
            }
        });
    });

    describe('encodeOid()', function () {
        it('throws an exception on empty OID', function (done) {
            try {
                asn1ber.encodeOid([]);
            } catch (err) {
                assert.equal("Minimum OID length is two.", err.message);
                done();
            }
        });
        it('throws an exception for incorrect SNMP OIDs', function (done) {
            try {
                asn1ber.encodeOid([1, 5, 6, 7, 8]);
            } catch (err) {
                assert.equal("SNMP OIDs always start with .1.3.", err.message);
                done();
            }
        });
        it('returns an oid correctly', function () {
            var oid = [1, 3, 6, 1, 4, 1, 2680, 1234567, 2, 7, 3, 2, 0];
            var correct = '06 0f 2b 06 01 04 01 94 78 cb ad 07 02 07 03 02 00'.replace(/ /g, '');
            var buf = asn1ber.encodeOid(oid);
            assert.equal(correct, buf.toString('hex'));
        });
    });

    describe('encodeRequest()', function () {
        it('returns a get request sequence', function () {
            var buf = asn1ber.encodeRequest(0, new Buffer(0));
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
            }
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
        it('correctly parses a negative integer', function () {
            assert.equal(-2, asn1ber.parseInteger(new Buffer('0201fe', 'hex')));
            assert.equal(-550, asn1ber.parseInteger(new Buffer('0202fdda', 'hex')));
            assert.equal(-1234567, asn1ber.parseInteger(new Buffer('0203ed2979', 'hex')));
            assert.equal(-123456789, asn1ber.parseInteger(new Buffer('0204f8a432eb', 'hex')))
        });
    });

    describe('parseOctetString()', function () {
        it('throws an exception when passed a non-octetstring buffer', function (done) {
            try {
                var buf = new Buffer('020100', 'hex');
                asn1ber.parseOctetString(buf);
            } catch (err) {
                done();
            }
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
        it('correctly parses a long string', function () {
            var buf = new Buffer('0481cf302d3031323334353637383920312d3031323334353637383920322d3031323334353637383920332d3031323334353637383920342d3031323334353637383920352d3031323334353637383920362d3031323334353637383920372d3031323334353637383920382d3031323334353637383920392d3031323334353637383920412d3031323334353637383920422d3031323334353637383920432d3031323334353637383920442d3031323334353637383920452d3031323334353637383920462d30313233343536373839', 'hex');
            var str = asn1ber.parseOctetString(buf);
            assert.equal('0-0123456789 1-0123456789 2-0123456789 3-0123456789 4-0123456789 5-0123456789 6-0123456789 7-0123456789 8-0123456789 9-0123456789 A-0123456789 B-0123456789 C-0123456789 D-0123456789 E-0123456789 F-0123456789', str);

            var veryLongString = "";
            for (var i = 0; i < 512; i++) {
                veryLongString = veryLongString + "foo"+i;
            }
            buf = asn1ber.encodeOctetString(veryLongString);
            str = asn1ber.parseOctetString(buf);
            assert.equal(veryLongString,str);
        });

    });

    describe('parseOid()', function () {
        it('throws an exception when passed a non-oid buffer', function (done) {
            try {
                var buf = new Buffer('020100', 'hex');
                asn1ber.parseOid(buf);
            } catch (err) {
                done();
            }
        });
        it('returns the shortest possible oid', function () {
            var buf = new Buffer('06012b', 'hex');
            var oid = asn1ber.parseOid(buf);
            assert.deepEqual([1, 3], oid);
        });
        it('correctly parses a random oid', function () {
            var correct = [1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 2, 0];
            var buf = new Buffer('06 0d 2b 06 01 04 01 94 78 01 02 07 03 02 00'.replace(/ /g, ''), 'hex');
            var oid = asn1ber.parseOid(buf);
            assert.deepEqual(correct, oid);
        });
        it('correctly parses a long oid with a large component', function () {
            var correct = [1, 3, 6, 1, 2, 1, 7, 7, 1, 8, 2, 16, 32, 1, 4, 112, 0, 39, 4, 214, 0, 0, 0, 0, 0, 0, 0, 2, 123, 0, 0, 0, 4179634304];
            var buf = new Buffer('06 252b 0601 0201 0707 0108 0210 2001 0470 0027 0481 5600 0000 0000 0000 027b 0000 008f c980 d100 0500'.replace(/ /g, ''), 'hex');
            var oid = asn1ber.parseOid(buf);
            assert.deepEqual(correct, oid);
        });
    });

    describe('parseArray()', function () {
        it('throws an exception when passed a non-array buffer', function (done) {
            try {
                var buf = new Buffer('020100', 'hex');
                asn1ber.parseArray(buf);
            } catch (err) {
                done();
            }
        });
        it('correctly parses a random array', function () {
            var correct = [0x30, 0x40, 0x16, 0x32];
            var buf = new Buffer('40 04 30 40 16 32'.replace(/ /g, ''), 'hex');
            var oid = asn1ber.parseArray(buf);
            assert.deepEqual(correct, oid);
        });
    });

    describe('parseOpaque()', function () {
        it('throws an exception when passed a non-opaque buffer', function (done) {
            try {
                var buf = new Buffer('020100', 'hex');
                asn1ber.parseOpaque(buf);
            } catch (err) {
                done();
            }
        });
        it('return the hex representation of an opaque value', function () {
            var correct = '0x9f78043e920000';
            var buf = new Buffer('44079f78043e920000', 'hex');
            var str = asn1ber.parseOpaque(buf);
            assert.deepEqual(correct, str);
        });
    });

    describe('lengthArray()', function () {
        it('returns the length directly if it\'s 127 or less', function () {
            assert.deepEqual([ 0 ], asn1ber.unittest.lengthArray(0));
            assert.deepEqual([ 47 ], asn1ber.unittest.lengthArray(47));
            assert.deepEqual([ 127 ], asn1ber.unittest.lengthArray(127));
        });
        it('returns the length as an encoded integer if greater than 127', function () {
            assert.deepEqual([ 128 + 1, 128 ], asn1ber.unittest.lengthArray(128));
            assert.deepEqual([ 128 + 2, 0x04, 0x01 ], asn1ber.unittest.lengthArray(1025));
        });
    });
});
