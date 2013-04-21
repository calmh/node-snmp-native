/*globals it:false, describe:false before:false after:false beforeEach:false
 */

var assert = require('assert');
var dgram = require('dgram');
var should = require('should');
var snmp = require('snmp');
var snmpsrv = require('snmpjs');

var agent = snmpsrv.createAgent();

var data = { '1.3.6.42.1.2.3': // No leading dot!
{
    '1': {
        '1': { type: 'OctetString', value: 'system description' },
        '2': { type: 'Counter64', value: 1234567890 },
        '3': { type: 'Integer', value: 1234567890 },
        '4': { type: 'TimeTicks', value: 1234567890 },
        '5': { type: 'Null', value: null },
        '6': { type: 'OctetString', value: new Buffer('001122334455', 'hex') },
        '7': { type: 'Counter32', value: 4294967295 },
        '8': { type: 'Counter64', value: { lo: 0xffffffff, hi: 0xffffffff }}, // As close to 2^64-1 as Javascript can get...
    }
},
    '1.3.6.42.1.2.4': {
        '1': {
            '1': { type: 'Opaque', value: new Buffer('11223344', 'hex') }
        }
    }
};

function setupResponder(agent, data) {
    Object.keys(data).forEach(function (oid) {
        var responses = data[oid];
        var columns = Object.keys(responses).map(function (x) {
            return parseInt(x, 10);
        });
        var handler = function (prq) {
            var lastPartOfOid, parts, col, inst, ival, val, vb, nextOid;

            lastPartOfOid = prq.oid.replace(oid, '').replace(/^\./, '');
            parts = lastPartOfOid.split('.').filter(function (s) {
                return s.length > 0;
            }).map(function (x) {
                return parseInt(x, 10);
            });

            if (prq.op === snmpsrv.pdu.GetRequest) {
                col = parts[0].toString();
                inst = parts[1].toString();
                ival = responses[col][inst].value;
                if (typeof ival === 'function') {
                    ival = ival();
                }
                val = snmpsrv.data.createData({ type: responses[col][inst].type, value: ival });
                vb = snmpsrv.varbind.createVarbind({ oid: prq.oid, data: val });
                prq.done(vb);
            } else if (prq.op === snmpsrv.pdu.GetNextRequest) {
                if (parts.length === 0 || parts.length > 2) {
                    col = columns[0];
                    inst = Object.keys(responses[col])[0];
                } else if (parts.length === 1) {
                    col = parts[0].toString();
                    inst = Object.keys(responses[col])[0];
                } else if (parts.length === 2) {
                    col = parts[0].toString();
                    inst = (parts[1] + 1).toString();
                    if (!responses[col][inst]) {
                        col = (parts[0] + 1).toString();
                        if (!responses[col]) {
                            return prq.done();
                        }
                        inst = Object.keys(responses[col])[0];
                    }
                }
                if (!col || !inst) {
                    prq.done()
                } else if (responses[col][inst]) {
                    nextOid = oid + '.' + col + '.' + inst;
                    ival = responses[col][inst].value;
                    if (typeof ival === 'function') {
                        ival = ival();
                    }
                    val = snmpsrv.data.createData({ type: responses[col][inst].type, value: ival });
                    vb = snmpsrv.varbind.createVarbind({ oid: nextOid, data: val });
                    prq.done(vb);
                } else {
                    prq.done();
                }
            }
        };
        agent.request({ oid: oid, columns: columns, handler: handler });
    });
}

setupResponder(agent, data);

agent.request({ oid: '.1.3.6.12.1.2.4', columns: [ 1 ], handler: function (prq) {
    var val, vb;

    if (!prq.instance) {
        return prq.done();
    }

    val = snmpsrv.data.createData({ type: 'Integer', value: prq.instance[0] });
    vb = snmpsrv.varbind.createVarbind({ oid: prq.oid, data: val });
    setTimeout(function () {
        prq.done(vb);
    }, prq.instance[0]);
} });

// Create a fake server that reponds with nonsense.

var server = dgram.createSocket('udp4');
server.on('message', function (msg, rinfo) {
    server.send(new Buffer(100), 0, 100, rinfo.port, rinfo.address);
});
server.bind(1162);

describe('integration', function () {
    before(function () {
        agent.bind({ family: 'udp4', port: 1161 });
    });

    after(function () {
        try {
            server.close();
            agent.close();
        } catch (err) {
        }
    });

    describe('get', function () {
        it('sets valid send and receive timestamps', function (done) {
            var session = new snmp.Session({ port: 1161 });
            var now = Date.now();
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 1] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].sendStamp.should.be.within(now, now + 50);
                    varbinds[0].receiveStamp.should.be.within(varbinds[0].sendStamp, now + 150);
                    done();
                }
            });
        });
        it('parses a single OctetString value', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 1] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 1]);
                    varbinds[0].value.should.equal('system description');
                    varbinds[0].valueHex.should.equal('73797374656d206465736372697074696f6e');
                    done();
                }
            });
        });
        it('parses a binary OctetString value', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 6] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 6]);
                    varbinds[0].valueHex.should.equal('001122334455');
                    done();
                }
            });
        });
        it('parses a single Counter64 value', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 2] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 2]);
                    varbinds[0].value.should.equal(1234567890);
                    done();
                }
            });
        });
        it('parses a single Integer value', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 3] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 3]);
                    varbinds[0].value.should.equal(1234567890);
                    done();
                }
            });
        });
        it('parses a single TimeTicks value', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 4] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 4]);
                    varbinds[0].value.should.equal(1234567890);
                    done();
                }
            });
        });
        it('parses a single null value', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 5] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 5]);
                    should.not.exist(varbinds[0].value);
                    done();
                }
            });
        });
        it('handles OIDs in string form', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: '.1.3.6.42.1.2.3.1.3' }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 3]);
                    varbinds[0].value.should.equal(1234567890);
                    done();
                }
            });
        });
        it('gracefully handles undefined oid', function (done) {
            var session = new snmp.Session();
            session.get({ }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(0);
                    done();
                }
            });
        });
        it('correctly understands a 2^32-1 Counter32', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: '.1.3.6.42.1.2.3.1.7' }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].value.should.equal(4294967295); // 2^32 - 1
                    done();
                }
            });
        });
        it('correctly understands a 2^64-1 Counter64', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: '.1.3.6.42.1.2.3.1.8' }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].value.should.equal(18446744073709552000); // 2^64 - 1, or as close as Javascripts float type comes.
                    done();
                }
            });
        });
    });

    describe('timouts', function () {
        it('should encode the send time in the request id', function (done) {
            var now = Date.now(), req;
            var session = new snmp.Session({ port: 1161, timeouts: [ 50 ] });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 1] }, function (err, varbinds) {
                should.not.exist(err);
                should.exist(varbinds);
                varbinds.length.should.equal(1);
                // Truncate to 22 bits
                now &= 0x1fffff;
                // The request id should be the truncated time in millis, shifted
                // ten bits to the left.
                req = varbinds[0].requestId >>> 10;
                (now - req).should.be.within(-5, 0);
                // The leftmost ten bits should be increasing for packets
                // sent the same millisecond. It should be at most two.
                req = varbinds[0].requestId & 0x3ff;
                req.should.be.within(1, 2);
                done();
            });
        });
        it('times out when the response takes longer than specified', function (done) {
            var session = new snmp.Session({ port: 1161, timeouts: [ 50 ] });
            session.get({ oid: [1, 3, 6, 12, 1, 2, 4, 1, 100] }, function (err, varbinds) {
                should.not.exist(varbinds);
                should.exist(err);
                done();
            });
        });
        it('does not time out when the timeout value is sufficient', function (done) {
            var session = new snmp.Session({ port: 1161, timeouts: [ 150 ] });
            session.get({ oid: [1, 3, 6, 12, 1, 2, 4, 1, 100] }, function (err, varbinds) {
                should.not.exist(err);
                should.exist(varbinds);
                done();
            });
        });
        it('does not time out when retransmits work', function (done) {
            var session = new snmp.Session({ port: 1161, timeouts: [ 50, 125 ] });
            session.get({ oid: '.1.3.6.12.1.2.4.1.100' }, function (err, varbinds) {
                should.not.exist(err);
                should.exist(varbinds);
                done();
            });
        });
    });

    describe('options', function () {
        beforeEach(function () {
            snmp.defaultOptions.host = 'localhost';
            snmp.defaultOptions.port = 161;
        });

        it('gets a response given global default values', function (done) {
            snmp.defaultOptions.host = 'localhost';
            snmp.defaultOptions.port = 1161;

            var session = new snmp.Session();
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 3] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 3]);
                    varbinds[0].value.should.equal(1234567890);
                    done();
                }
            });
        });
        it('gets a response given session default values', function (done) {
            snmp.defaultOptions.host = 'example.com';
            snmp.defaultOptions.port = 999;

            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 3] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 3]);
                    varbinds[0].value.should.equal(1234567890);
                    done();
                }
            });
        });
        it('gets a response given explicit values', function (done) {
            snmp.defaultOptions.host = 'example.com';
            snmp.defaultOptions.port = 999;

            var session = new snmp.Session({ host: 'example.com', port: 999 });
            session.get({ host: 'localhost', port: 1161, oid: [1, 3, 6, 42, 1, 2, 3, 1, 3] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 3]);
                    varbinds[0].value.should.equal(1234567890);
                    done();
                }
            });
        });
    });

    describe('getAll', function () {
        it('should get an array of oids', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            var oids = [
                [1, 3, 6, 42, 1, 2, 3, 1, 1],
                [1, 3, 6, 42, 1, 2, 3, 1, 2],
                [1, 3, 6, 42, 1, 2, 3, 1, 3],
                [1, 3, 6, 42, 1, 2, 3, 1, 4],
                [1, 3, 6, 42, 1, 2, 3, 1, 5]
            ];
            // We need more than 16 oids to test sending more than one packet.
            var manyOids = [].concat(oids, oids, oids, oids);
            assert.equal(20, manyOids.length);
            session.getAll({ oids: manyOids }, function (err, vbs) {
                if (err) {
                    done(err);
                } else {
                    vbs.length.should.equal(20);
                    for (var i = 0; i < 4; i++) {
                        vbs[5 * i + 0].value.should.equal('system description');
                        vbs[5 * i + 1].value.should.equal(1234567890);
                        vbs[5 * i + 2].value.should.equal(1234567890);
                        vbs[5 * i + 3].value.should.equal(1234567890);
                        should.not.exist(vbs[5 * i + 4].value);
                    }
                    done();
                }
            });
        });
        it('should get an array of oids in string form', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            var oids = [ '.1.3.6.42.1.2.3.1.1', '.1.3.6.42.1.2.3.1.2', '.1.3.6.42.1.2.3.1.3', '.1.3.6.42.1.2.3.1.4', '.1.3.6.42.1.2.3.1.5' ];
            session.getAll({ oids: oids }, function (err, vbs) {
                if (err) {
                    done(err);
                } else {
                    vbs.length.should.equal(5);
                    vbs[0].value.should.equal('system description');
                    vbs[1].value.should.equal(1234567890);
                    vbs[2].value.should.equal(1234567890);
                    vbs[3].value.should.equal(1234567890);
                    should.not.exist(vbs[4].value);
                    done();
                }
            });
        });
        it('should get an array of oids from specific host and community', function (done) {
            var session = new snmp.Session();
            var oids = [
                [1, 3, 6, 42, 1, 2, 3, 1, 1],
                [1, 3, 6, 42, 1, 2, 3, 1, 2],
                [1, 3, 6, 42, 1, 2, 3, 1, 3],
                [1, 3, 6, 42, 1, 2, 3, 1, 4],
                [1, 3, 6, 42, 1, 2, 3, 1, 5]
            ];
            session.getAll({ oids: oids, host: 'localhost', community: 'any', port: 1161 }, function (err, vbs) {
                if (err) {
                    done(err);
                } else {
                    vbs.length.should.equal(5);
                    vbs[0].value.should.equal('system description');
                    vbs[1].value.should.equal(1234567890);
                    vbs[2].value.should.equal(1234567890);
                    vbs[3].value.should.equal(1234567890);
                    should.not.exist(vbs[4].value);
                    done();
                }
            });
        });
        it('gracefully handles undefined oids', function (done) {
            var session = new snmp.Session();
            session.getAll({ }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(0);
                    done();
                }
            });
        });
        it('gracefully handles empty oids list', function (done) {
            var session = new snmp.Session();
            session.getAll({ oids: [] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(0);
                    done();
                }
            });
        });
        it('should throw an error for invalid oid', function () {
            var session = new snmp.Session();
            var test = function () {
                session.getNext({ oids: [ '1.3.6.42.1.2.3.1' ] }, function (err, vbs) {
                });
            };
            test.should.throw(/Invalid OID format/);
        });
    });

    describe('getNext', function () {
        it('should get a new value', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.getNext({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 5] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 6]);
                    varbinds[0].valueHex.should.equal('001122334455');
                    done();
                }
            });
        });
        it('should get a new value with oid in string form', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.getNext({ oid: '.1.3.6.42.1.2.3.1.5' }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 6]);
                    varbinds[0].valueHex.should.equal('001122334455');
                    done();
                }
            });
        });
        it('gracefully handles undefined oid', function (done) {
            var session = new snmp.Session();
            session.getNext({ }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(0);
                    done();
                }
            });
        });
        it('should throw an error for invalid oid', function () {
            var session = new snmp.Session();
            var test = function () {
                session.getNext({ oid: '1.3.6.42.1.2.3.1' }, function (err, vbs) {
                });
            };
            test.should.throw(/Invalid OID format/);
        });
    });

    describe('getSubtree', function () {
        it('should get a complete tree', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.getSubtree({ oid: [1, 3, 6, 42, 1, 2, 3, 1] }, function (err, vbs) {
                if (err) {
                    done(err);
                } else {
                    vbs.length.should.equal(8);
                    vbs[0].value.should.equal('system description');
                    vbs[1].value.should.equal(1234567890);
                    vbs[2].value.should.equal(1234567890);
                    vbs[3].value.should.equal(1234567890);
                    should.not.exist(vbs[4].value);
                    vbs[5].valueHex.should.equal('001122334455');
                    done();
                }
            });
        });
        it('should get a complete tree with oid in string form', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.getSubtree({ oid: '.1.3.6.42.1.2.4.1' }, function (err, vbs) {
                if (err) {
                    done(err);
                } else {
                    vbs.length.should.equal(1);
                    vbs[0].value.should.equal('0x11223344'); // Opaque
                    done();
                }
            });
        });
        it('gracefully handles undefined oid', function (done) {
            var session = new snmp.Session();
            session.getSubtree({ }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(0);
                    done();
                }
            });
        });
        it('should throw an error for invalid oid', function () {
            var session = new snmp.Session();
            var test = function () {
                session.get({ oid: '1.3.6.42.1.2.3.1' }, function (err, vbs) {
                });
            };
            test.should.throw(/Invalid OID format/);
        });
    });

    describe('set', function () {
        it('should throw an error for unknown value types', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            var test = function () {
                session.set({ oid: [1, 3, 6, 42, 1, 2, 3, 1], value: 5, type: 4 }, function (err, vbs) {
                });
            };
            test.should.throw();
        });
        it('should not throw an error for integer type', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.set({ oid: [1, 3, 6, 42, 1, 2, 3, 1], value: 5, type: 2 }, function (err, vbs) {
            });
        });
        it('should gracefully handle an undefined callback', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.set({ oid: [1, 3, 6, 42, 1, 2, 3, 1], value: 5, type: 2 });
        });
        it('should not throw an error for string oid', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            var test = function () {
                session.set({ oid: '.1.3.6.42.1.2.3.1', value: 5, type: 2 }, function (err, vbs) {
                });
            };
            test.should.not.throw();
        });
        it('should not throw an error for value zero', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            var test = function () {
                session.set({ oid: '.1.3.6.42.1.2.3.1', value: 0, type: 2 }, function (err, vbs) {
                });
            };
            test.should.not.throw();
        });
        it('should not throw an error for IP number value', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            var test = function () {
                session.set({ oid: '.1.3.6.42.1.2.3.1', value: '172.16.32.64', type: 0x40 }, function (err, vbs) {
                });
            };
            test.should.not.throw();
        });
        it('should throw an error for missing oid', function () {
            var session = new snmp.Session();
            var test = function () {
                session.set({ value: 5, type: 2 }, function (err, vbs) {
                });
            };
            test.should.throw(/Missing required option/);
        });
        it('should throw an error for invalid oid', function () {
            var session = new snmp.Session();
            var test = function () {
                session.set({ oid: '1.3.6.42.1.2.3.1', value: 5, type: 2 }, function (err, vbs) {
                });
            };
            test.should.throw(/Invalid OID format/);
        });
        it('should throw an error for missing value', function () {
            var session = new snmp.Session();
            var test = function () {
                session.set({ oid: '.1.3.6.42.1.2.3.1', type: 2 }, function (err, vbs) {
                });
            };
            test.should.throw(/Missing required option/);
        });
        it('should throw an error for missing type', function () {
            var session = new snmp.Session();
            var test = function () {
                session.set({ oid: '.1.3.6.42.1.2.3.1', value: 42 }, function (err, vbs) {
                });
            };
            test.should.throw(/Missing required option/);
        });
    });

    describe('errors', function () {
        it('should return a noSuchObject varbind', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.get({ oid: [1, 3, 6, 0] }, function (err, varbinds) {
                should.not.exist(err);
                should.exist(varbinds);
                varbinds.length.should.equal(1);
                varbinds[0].type.should.equal(128);
                varbinds[0].value.should.equal('noSuchObject');
                done();
            });
        });
        it('should return a noSuchInstance varbind', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1] }, function (err, varbinds) {
                should.not.exist(err);
                should.exist(varbinds);
                varbinds.length.should.equal(1);
                varbinds[0].type.should.equal(129);
                varbinds[0].value.should.equal('noSuchInstance');
                done();
            });
        });
        it('should return an error for nonexistant host', function (done) {
            var session = new snmp.Session({ host: '1.2.427.5' });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1] }, function (err, varbinds) {
                should.exist(err);
                should.not.exist(varbinds);
                done();
            });
        });
        it('should return an error for host of the wrong address family', function (done) {
            // This actually results in a timeout. That works, I guess, since it indicates
            // a communication problem. I would have expected something more immediate.
            var session = new snmp.Session({ family: 'udp4', host: '2001:db8::1', timeouts: [ 100 ] });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1] }, function (err, varbinds) {
                should.exist(err);
                should.not.exist(varbinds);
                done();
            });
        });
        it('should throw a parse error when the recieved data makes no sense', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1162 });
            session.on('error', function () {
                done();
            });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1] }, function (err, varbinds) {
            });
        });
    });
});

