var _ = require('underscore');
var asn1ber = require('./asn1ber');

function VarBind() {
    this.oid = null;
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
    version = asn1ber.integer(pkt.version);
    community = asn1ber.octetString(pkt.community);

    // PDU header fields 
    reqid = asn1ber.integer(pkt.pdu.reqid);
    err = asn1ber.integer(pkt.pdu.error);
    erridx = asn1ber.integer(pkt.pdu.errorIndex);

    // PDU varbinds
    vbs = [];
    _.each(pkt.pdu.varbinds, function (vb) {
        var oid = asn1ber.oid(vb.oid);
        var val;
        if (vb.type === 5) { // null
            val = asn1ber.null();
        }
        vbs.push(asn1ber.sequence(concatBuffers([oid, val])));
    });
    vbs = asn1ber.sequence(concatBuffers(vbs));

    pdu = asn1ber.request(pkt.pdu.type, concatBuffers([reqid, err, erridx, vbs]));
    message = asn1ber.sequence(concatBuffers([version, community, pdu]));
    return message;
};

