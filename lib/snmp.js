// This file implements a structure representing an SNMP message
// and routines for converting to and from the network representation.
//
// (c) 2012 Jakob Borg, Nym Networks

var _ = require('underscore');
var asn1ber = require('./asn1ber');
var assert = require('assert');

// Basic structures
// ----

// A `VarBind` is the innermost structure, containing an OID-Value pair.
function VarBind() {
    this.encodeOid = null;
    this.type = 5;
    this.value = null;
}

// The `PDU` contains the SNMP request or response fields and a list of `VarBinds`.
function PDU() {
    this.type = 0;
    this.reqid = 1;
    this.error = 0;
    this.errorIndex = 0;
    this.varbinds = [ new VarBind() ];
}

// The `Packet` contains the SNMP version and community and the `PDU`.
function Packet() {
    this.version = 1;
    this.community = 'public';
    this.pdu = new PDU();
}

// Allow consumers to create packet structures from scratch.
exports.Packet = Packet;

// Private helper functions
// ----

// Concatenate several buffers to one.
function concatBuffers(buffers) {
    var total = 0, cur = 0;

    // First we calculate the total length,
    _.each(buffers, function (buffer) {
        total += buffer.length;
    });

    // then we allocate a new Buffer large enough to contain all data,
    var buf = new Buffer(total);
    _.each(buffers, function (buffer) {
        // finally we copy the data into the new larger buffer.
        buffer.copy(buf, cur, 0);
        cur += buffer.length;
    });

    return buf;
}

// Encode structure to ASN.1 BER
// ----

// Return an ASN.1 BER encoding of a Packet structure.
// This is suitable for transmission on a UDP socket.
exports.encode = function (pkt) {
    var version, community, reqid, err, erridx, vbs, pdu, message;

    // We only support SNMPv2c, so enforce that version stamp.
    if (pkt.version !== 1) {
        throw new Error('Only SNMPv2c is supported.');
    }

    // Encode the message header fields.
    version = asn1ber.encodeInteger(pkt.version);
    community = asn1ber.encodeOctetString(pkt.community);

    // Encode the PDU header fields.
    reqid = asn1ber.encodeInteger(pkt.pdu.reqid);
    err = asn1ber.encodeInteger(pkt.pdu.error);
    erridx = asn1ber.encodeInteger(pkt.pdu.errorIndex);

    // Encode the PDU varbinds.
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

    // Concatenate all the varbinds together.
    vbs = asn1ber.encodeSequence(concatBuffers(vbs));

    // Create the PDU by concatenating the inner fields and adding a request structure around it.
    pdu = asn1ber.encodeRequest(pkt.pdu.type, concatBuffers([reqid, err, erridx, vbs]));

    // Create the message by concatenating the header fields and the PDU.
    message = asn1ber.encodeSequence(concatBuffers([version, community, pdu]));

    return message;
};

// Parse ASN.1 BER into a structure
// -----

// Parse an SNMP packet into its component fields.
// We don't do a lot of validation so a malformed packet will probably just
// make us blow up.

exports.parse = function (buf) {
    var pkt, oid, bvb, vb;

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
        vb = new VarBind();

        // The OID
        bvb = buf.slice(2);
        vb.oid = asn1ber.parseOid(bvb);

        // The value
        bvb = bvb.slice(2 + bvb[1]);
        vb.type = bvb[0]
        if (vb.type === asn1ber.types.Null) {
            vb.value = null;
        } else if (vb.type === asn1ber.types.OctetString) {
            vb.value = asn1ber.parseOctetString(bvb);
        } else if (vb.type === asn1ber.types.Integer ||
                   vb.type == asn1ber.types.Counter ||
                       vb.type === asn1ber.types.Counter64 ||
                       vb.type === asn1ber.types.TimeTicks ||
                       vb.type === asn1ber.types.Gauge) {
            vb.value = asn1ber.parseInteger(bvb);
        } else {
            throw new Error('Unrecognized value type ' + vb.type);
        }
        pkt.pdu.varbinds.push(vb);

        // Next varbind, if any
        buf = buf.slice(2 + buf[1]);
    };

    return pkt;
};

