var _ = require('underscore');
var asn1ber = require('./asn1ber');
var assert = require('assert');

function VarBind() {
    this.encodeOid = null;
    this.type = 5;
    this.value = null;
}

function PDU() {
    this.type = 0;
    this.reqid = 1;
    this.error = 0;
    this.errorIndex = 0;
    this.varbinds = [ new VarBind() ];
}

function Packet() {
    this.version = 1;
    this.community = 'public';
    this.pdu = new PDU();
}

exports.Packet = Packet;

function concatBuffers(buffers) {
    var total = 0, cur = 0;
    _.each(buffers, function (buffer) {
        total += buffer.length;
    });

    var buf = new Buffer(total);
    _.each(buffers, function (buffer) {
        buffer.copy(buf, cur, 0);
        cur += buffer.length;
    });

    return buf;
}

exports.encode = function (pkt) {
    var version, community, reqid, err, erridx, vbs, pdu, message;

    // Packet checks
    if (pkt.version !== 1) {
        throw new Error('Only SNMPv2c is supported.');
    }

    // Message header fields
    version = asn1ber.encodeInteger(pkt.version);
    community = asn1ber.encodeOctetString(pkt.community);

    // PDU header fields 
    reqid = asn1ber.encodeInteger(pkt.pdu.reqid);
    err = asn1ber.encodeInteger(pkt.pdu.error);
    erridx = asn1ber.encodeInteger(pkt.pdu.errorIndex);

    // PDU varbinds
    vbs = [];
    _.each(pkt.pdu.varbinds, function (vb) {
        var oid = asn1ber.encodeOid(vb.oid);
        var val;
        if (vb.type === asn1ber.types.Null) {
            val = asn1ber.encodeNull();
        } else {
            throw new Error('Unknown varbind type "' + vb.type + '" in encoding.');
        }
        vbs.push(asn1ber.encodeSequence(concatBuffers([oid, val])));
    });
    vbs = asn1ber.encodeSequence(concatBuffers(vbs));

    pdu = asn1ber.encodeRequest(pkt.pdu.type, concatBuffers([reqid, err, erridx, vbs]));
    message = asn1ber.encodeSequence(concatBuffers([version, community, pdu]));
    return message;
};

// Parse an SNMP packet into its component fields.
// We don't do a lot of validation so a malformed packet will probably just
// make us blow up.

exports.parse = function (buf) {
    var pkt;

    pkt = new Packet();

    // First we have a sequence marker (two bytes).
    // We don't care about those, so cut them off.
    assert.equal(asn1ber.types.Sequence, buf[0]);
    buf = buf.slice(2);

    // Then comes the version field (integer). Parse it and slice it.
    pkt.version = asn1ber.parseInteger(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // We then get the community. Parse and slice.
    pkt.community = asn1ber.parseOctetString(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // Here's the PDU structure. We're interested in the type. Slice the rest.
    assert.ok(buf[0] >= 0xA0);
    pkt.pdu.type = buf[0] - 0xA0;
    buf = buf.slice(2);

    // The request id field.
    pkt.pdu.reqid = asn1ber.parseInteger(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // The error field.
    pkt.pdu.error = asn1ber.parseInteger(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // The error index field.
    pkt.pdu.errorIndex = asn1ber.parseInteger(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // Here's the varbind list. Not interested.
    assert.equal(asn1ber.types.Sequence, buf[0]);
    buf = buf.slice(2);

    // Now comes the varbinds. There might be many, so we loop for as long as we have data.
    pkt.pdu.varbinds = [];
    while (buf[0] == asn1ber.types.Sequence) {
        // ...
        buf = buf.slice(2 + buf[1]);
    };

    return pkt;
};

