var _ = require('underscore');
var asn1ber = require('./asn1ber');

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

exports.ber = function (pkt) {
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

