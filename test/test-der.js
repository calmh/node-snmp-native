var assert = require('assert');
var der = require('der');

describe('DER', function () {
    describe('#integer()', function () {
        it('returns one byte for zero', function () {
            var buf = der.integer(0);
            assert.equal(3, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(1, buf[1]); // Length
            assert.equal(0, buf[2]); // Value
        });
        it('returns one byte for one', function () {
            var buf = der.integer(1);
            assert.equal(3, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(1, buf[1]); // Length
            assert.equal(1, buf[2]); // Value
        });
        it('returns correctly for larger integer', function () {
            var buf = der.integer(1234567890);
            assert.equal(6, buf.length);
            assert.equal(2, buf[0]); // Integer
            assert.equal(4, buf[1]); // Length
            assert.equal(73, buf[2]); // Value
            assert.equal(150, buf[3]); // Value
            assert.equal(2, buf[4]); // Value
            assert.equal(210, buf[5]); // Value
        });
    });

    describe('#null()', function () {
        it('returns the null representation', function () {
            var buf = der.null();
            assert.equal(2, buf.length);
            assert.equal(5, buf[0]); // Null
            assert.equal(0, buf[1]); // Zero
        });
    });

    describe('#sequence()', function () {
        it('returns an empty sequence', function () {
            var buf = der.sequence(new Buffer(0));
            assert.equal(2, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(0, buf[1]); // Zero length
        });
        it('returns wrapped sequence', function () {
            var buf = der.sequence(new Buffer(10));
            assert.equal(12, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(10, buf[1]); // Length
        });
        it('does not modify the passed data', function () {
            var orig = new Buffer(10);
            for (i = 0; i < 10; i++) {
                orig[i] = i;
            }

            var buf = der.sequence(orig);
            var i;
            assert.equal(12, buf.length);
            assert.equal(0x30, buf[0]); // Sequence
            assert.equal(10, buf[1]); // Length
            for (i = 0; i < 10; i++) {
                assert.equal(i, buf[i+2]);
            }
        });
    });

    describe('#octetString()', function () {
        it('returns an empty string', function () {
            var buf = der.octetString('');
            assert.equal(2, buf.length);
            assert.equal(4, buf[0]); // OctetString
            assert.equal(0, buf[1]); // Zero length
        });
        it('returns a simple string correctly', function () {
            var str = 'abc';
            var buf = der.octetString(str);
            var i;
            assert.equal(5, buf.length);
            assert.equal(4, buf[0]); // OctetString
            assert.equal(str.length, buf[1]); // Length
            for (i = 0; i < str.length; i++) {
                assert.equal(str.charCodeAt(i), buf[i+2]);
            }
        });
    });

    describe('#oid()', function () {
        it('throws an exception on empty OID', function (done) {
            try {
                der.oid([]);
            } catch (err) {
                assert.equal("Minimum OID length is two.", err.message);
                done();
            }
        });
        it('throws an exception for incorrect SNMP OIDs', function (done) {
            try {
                der.oid([1, 5, 6, 7, 8]);
            } catch (err) {
                assert.equal("SNMP OIDs always start with .1.3.", err.message);
                done();
            }
        });
        it('returns an oid correctly', function () {
            var oid = [1,3,6,1,4,1,2680,1,2,7,3,2,0];
            var buf = der.oid(oid);
            assert.equal(15, buf.length);
            assert.equal(6, buf[0]); // OID
            assert.equal(13, buf[1]); // Length
            // from http://www.rane.com/note161.html
            assert.equal(0x2B, buf[2]);
            assert.equal(0x06, buf[3]);
            assert.equal(0x01, buf[4]);
            assert.equal(0x04, buf[5]);
            assert.equal(0x01, buf[6]);
            assert.equal(0x94, buf[7]);
            assert.equal(0x78, buf[8]);
            assert.equal(0x01, buf[9]);
            assert.equal(0x02, buf[10]);
            assert.equal(0x07, buf[11]);
            assert.equal(0x03, buf[12]);
            assert.equal(0x02, buf[13]);
            assert.equal(0x00, buf[14]);
        });
    });

    describe('#getRequest()', function () {
        it('returns a get request sequence', function () {
            var buf = der.getRequest(new Buffer(0));
            assert.equal(2, buf.length);
            assert.equal(160, buf[0]); // GetRequest
            assert.equal(0, buf[1]); // Zero length
        });
    });
});
