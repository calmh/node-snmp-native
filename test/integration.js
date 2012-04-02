var snmpsrv = require('snmpjs');
var assert = require('assert');
var snmp = require('snmp');
var should = require('should');

var agent = snmpsrv.createAgent();

agent.request({ oid: '.1.3.6.42.1.2.3', columns: [ 1 ], handler: function (prq) {
    var val, vb;
    if (prq.op === snmpsrv.pdu.GetRequest) {
        if (prq.instance[0] === 1) {
            val = snmpsrv.data.createData({ type: 'OctetString', value: 'system description' });
        } else if (prq.instance[0] === 2) {
            val = snmpsrv.data.createData({ type: 'Counter64', value: 1234567890 });
        } else if (prq.instance[0] === 3) {
            val = snmpsrv.data.createData({ type: 'Integer', value: 1234567890 });
        } else if (prq.instance[0] === 4) {
            val = snmpsrv.data.createData({ type: 'TimeTicks', value: 1234567890 });
        } else if (prq.instance[0] === 5) {
            val = snmpsrv.data.createData({ type: 'Null', value: null });
        }
        vb = snmpsrv.varbind.createVarbind({ oid: prq.oid, data: val });
        prq.done(vb);
    } else if (prq.op === snmpsrv.pdu.GetNextRequest) {
        var oid, last;

        oid = prq.addr;
        if (prq.instance) {
            last = prq.instance[0] + 100;
            oid.pop();
        } else {
            last = 1;
        }
        if (last < 1000) {
            oid.push(last);
            oid = '.' + oid.join('.');

            val = snmpsrv.data.createData({ type: 'Integer', value: last });
            vb = snmpsrv.varbind.createVarbind({ oid: oid, data: val });
            prq.done(vb);
        } else {
            prq.done();
        }
    }
} });

agent.request({ oid: '.1.3.6.99.1.2.4', columns: [ 1 ], handler: function (prq) {
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

describe('integration', function () {
    before(function () {
        agent.bind({ family: 'udp4', port: 1161 });
    });

    after(function () {
        try {
            agent.close();
        } catch (err) {
        }
    });

    describe('get', function () {
        it('parses a single OctetString value', function (done) {
            var session = new snmp.Session({ port: 1161 });
            session.get({ oid: [1, 3, 6, 42, 1, 2, 3, 1, 1] }, function (err, varbinds) {
                if (err) {
                    done(err);
                } else {
                    varbinds.length.should.equal(1);
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 1]);
                    varbinds[0].value.should.equal('system description');
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
    });

    describe('timouts', function () {
        it('times out when the response takes longer than specified', function (done) {
            var session = new snmp.Session({ port: 1161, timeouts: [ 50 ] });
            session.get({ oid: [1, 3, 6, 99, 1, 2, 4, 1, 100] }, function (err, varbinds) {
                should.not.exist(varbinds);
                should.exist(err);
                done();
            });
        });
        it('does not time out when the timeout value is sufficient', function (done) {
            var session = new snmp.Session({ port: 1161, timeouts: [ 150 ] });
            session.get({ oid: [1, 3, 6, 99, 1, 2, 4, 1, 100] }, function (err, varbinds) {
                should.not.exist(err);
                should.exist(varbinds);
                done();
            });
        });
        it('does not time out when retransmits work', function (done) {
            var session = new snmp.Session({ port: 1161, timeouts: [ 50, 125 ] });
            session.get({ oid: [1, 3, 6, 99, 1, 2, 4, 1, 100] }, function (err, varbinds) {
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
            var oids = [ [1, 3, 6, 42, 1, 2, 3, 1, 1], [1, 3, 6, 42, 1, 2, 3, 1, 2], [1, 3, 6, 42, 1, 2, 3, 1, 3], [1, 3, 6, 42, 1, 2, 3, 1, 4], [1, 3, 6, 42, 1, 2, 3, 1, 5] ];
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
                };
            });
        });
        it('should get an array of oids from specific host and community', function (done) {
            var session = new snmp.Session();
            var oids = [ [1, 3, 6, 42, 1, 2, 3, 1, 1], [1, 3, 6, 42, 1, 2, 3, 1, 2], [1, 3, 6, 42, 1, 2, 3, 1, 3], [1, 3, 6, 42, 1, 2, 3, 1, 4], [1, 3, 6, 42, 1, 2, 3, 1, 5] ];
            session.getAll({ oids: oids, host: 'localhost', community: 'any', port: 1161 }, function (err, vbs) {
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
                };
            });
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
                    varbinds[0].oid.should.eql([1, 3, 6, 42, 1, 2, 3, 1, 105]);
                    varbinds[0].value.should.equal(105);
                    done();
                };
            });
        });
    });

    describe('getSubtree', function () {
        it('should get a complete tree', function (done) {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            session.getSubtree({ oid: [1, 3, 6, 42, 1, 2, 3, 1] }, function (err, vbs) {
                if (err) {
                    done(err);
                } else {
                    vbs.length.should.equal(10);
                    for (var i = 0; i < 10; i++) {
                        vbs[i].type.should.equal(2);
                        vbs[i].value.should.equal(1 + i * 100);
                        vbs[i].oid.pop().should.equal(1 + i * 100);
                    }
                    done();
                };
            });
        });
    });

    describe('set', function () {
        it('should throw an error for unknown value types', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            (function () {
                session.set({ oid: [1, 3, 6, 42, 1, 2, 3, 1], value: 5, type: 4 }, function (err, vbs) { });
            }).should.throw();
        });
        it('should not throw an error for integer type', function () {
            var session = new snmp.Session({ host: 'localhost', port: 1161 });
            (function () {
                session.set({ oid: [1, 3, 6, 42, 1, 2, 3, 1], value: 5, type: 2 }, function (err, vbs) { });
            }).should.not.throw();
        });
    });
});

