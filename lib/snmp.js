// This file implements a structure representing an SNMP message
// and routines for converting to and from the network representation.
//
// (c) 2012 Jakob Borg, Nym Networks

var _ = require('underscore');
var asn1ber = require('./asn1ber');
var assert = require('assert');
var dgram = require('dgram');

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

// Parse and return type, data length and header length.
function typeLength(buf) {
    var res, len, i;

    res = { type: buf[0], len: 0, header: 1 };
    if (buf[1] < 128) {
        // If bit 8 is zero, this byte indicates the content length (up to 127 bytes).
        res.len = buf[1];
        res.header += 1;
    } else {
        // If bit 8 is 1, bits 0 to 7 indicate the number of following legth bytes.
        // These bytes are a simple msb base-256 integer indicating the content length.
        for (i = 0; i < buf[1] - 128; i++) {
            res.len += buf[i + 1];
            res.len *= 256;
        }
        res.header += buf[1] - 128 + 1;
    }
    return res;
}

// Display useful debugging information when a parse error occurs.
function parseError(error, buffer) {
    var hex;

    // Display a friendly introductory text.
    console.error('Woops! An error occurred while parsing an SNMP message. :(');
    console.error('To have this problem corrected, please report the information below verbatim');
    console.error('via email to snmp@nym.se or by creating a GitHub issue at');
    console.error('https://github.com/calmh/node-snmp-native/issues');
    console.error('');
    console.error('Thanks!');

    // Display the stack backtrace so we know where the exception happened.
    console.error('');
    console.error(error.stack);

    // Display the buffer data, nicely formatted so we can replicate the problem.
    console.error('\nMessage data:');
    hex = buffer.toString('hex');
    while (hex.length > 0) {
        console.error('    ' + hex.slice(0, 32).replace(/([0-9a-f]{2})/g, '$1 '));
        hex = hex.slice(32);
    }

    // Let the exception bubble upwards.
    throw error;
}

// Encode structure to ASN.1 BER
// ----

// Return an ASN.1 BER encoding of a Packet structure.
// This is suitable for transmission on a UDP socket.
function encode(pkt) {
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

exports.encode = encode;

// Parse ASN.1 BER into a structure
// -----

// Parse an SNMP packet into its component fields.
// We don't do a lot of validation so a malformed packet will probably just
// make us blow up.

function parse(buf) {
    var pkt, oid, bvb, vb, hdr;

    pkt = new Packet();

    // First we have a sequence marker (two bytes).
    // We don't care about those, so cut them off.
    hdr = typeLength(buf);
    assert.equal(asn1ber.types.Sequence, hdr.type);
    buf = buf.slice(hdr.header);

    // Then comes the version field (integer). Parse it and slice it.
    pkt.version = asn1ber.parseInteger(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // We then get the community. Parse and slice.
    pkt.community = asn1ber.parseOctetString(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // Here's the PDU structure. We're interested in the type. Slice the rest.
    hdr = typeLength(buf);
    assert.ok(hdr.type >= 0xA0);
    pkt.pdu.type = hdr.type - 0xA0;
    buf = buf.slice(hdr.header);

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
    hdr = typeLength(buf);
    assert.equal(asn1ber.types.Sequence, hdr.type);
    buf = buf.slice(hdr.header);

    // Now comes the varbinds. There might be many, so we loop for as long as we have data.
    pkt.pdu.varbinds = [];
    while (buf[0] == asn1ber.types.Sequence) {
        vb = new VarBind();

        // Slice of the sequence header
        hdr = typeLength(buf);
        assert.equal(asn1ber.types.Sequence, hdr.type);
        bvb = buf.slice(hdr.header);

        // The OID
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
        } else if (vb.type === asn1ber.types.ObjectIdentifier) {
            vb.value = asn1ber.parseOid(bvb);
        } else if (vb.type === asn1ber.types.IpAddress) {
            vb.value = asn1ber.parseArray(bvb);
        } else {
            throw new Error('Unrecognized value type ' + vb.type);
        }
        pkt.pdu.varbinds.push(vb);

        // Next varbind, if any
        if (buf.length > hdr.header + hdr.len) {
            buf = buf.slice(hdr.header + hdr.len);
        } else {
            break;
        }
    };

    return pkt;
};

exports.parse = parse;

// Communication functions
// -----

function msgReceived(msg, rinfo) {
    var self = this, pkt;

    try {
        pkt = parse(msg);
    } catch (error) {
        return parseError(error, msg);
    }

    if (self.reqs[pkt.pdu.reqid]) {
        self.reqs[pkt.pdu.reqid](null, pkt);
        self.reqs[pkt.pdu.reqid] = undefined;
    }
}

function Session(destination, community, family) {
    var self = this;

    family = family || 'udp4';
    self.destination = destination;
    self.community = community;
    self.reqs = {};
    self.socket = dgram.createSocket(family);
    self.socket.on('message', _.bind(msgReceived, self));
}

Session.prototype.sendMsg = function (pkt, callback) {
    var self = this, buf, reqid;

    reqid = parseInt(Math.random() * 65536 * 65536, 10);
    pkt.pdu.reqid = reqid
    buf = encode(pkt);
    self.socket.send(buf, 0, buf.length, 161, self.destination, function (err, bytes) {
        if (err) {
            callback(err);
        } else {
            self.reqs[reqid] = callback;
        }
    });
}

Session.prototype.get = function (oid, callback) {
    var self = this, pkt;

    pkt = new Packet();
    pkt.community = self.community;
    pkt.pdu.varbinds[0].oid = oid;
    self.sendMsg(pkt, callback);
};

Session.prototype.getNext = function (oid, callback) {
    var self = this, pkt;

    pkt = new Packet();
    pkt.community = self.community;
    pkt.pdu.type = 1;
    pkt.pdu.varbinds[0].oid = oid;
    self.sendMsg(pkt, callback);
};

Session.prototype.close = function () {
    this.socket.close();
}

exports.Session = Session;

