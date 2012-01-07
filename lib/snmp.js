// Introduction
// -----
// This is `node-snmp-native`, a native (Javascript) implementation of an SNMP
// client library targeted at Node.js. It's MIT licensed and available at
// https://github.com/calmh/node-snmp-native
//
// (c) 2012 Jakob Borg, Nym Networks

// Code
// -----
// This file implements a structure representing an SNMP message
// and routines for converting to and from the network representation.

// Define our external dependencies.
var _ = require('underscore');
var assert = require('assert');
var dgram = require('dgram');

// We also need our ASN.1 BER en-/decoding routines.
var asn1ber = require('./asn1ber');

// Here we define an array defining the timeout/retransmi behaviour of the library.
// The values are in milliseconds and define the timeout since the previous request.
// Thus the first element will define how many ms we wait before retransmission of
// the original request, the second element how many ms we wait before retransmission
// after that, etc. When there are no more elements, a Timeout error is raised instead.
// An increasing sequence resembling an exponential backoff is probably useful. More than
// five retransmits are seldom fruitful.
var RETRANSMISSIONS = [ 250, 500, 1000, 2500, 5000 ];

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
    var total = 0, cur = 0, buf;

    // First we calculate the total length,
    _.each(buffers, function (buffer) {
        total += buffer.length;
    });

    // then we allocate a new Buffer large enough to contain all data,
    buf = new Buffer(total);
    _.each(buffers, function (buffer) {
        // finally we copy the data into the new larger buffer.
        buffer.copy(buf, cur, 0);
        cur += buffer.length;
    });

    return buf;
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
        var oid = asn1ber.encodeOid(vb.oid), val;
        
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
}

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
    hdr = asn1ber.typeAndLength(buf);
    assert.equal(asn1ber.types.Sequence, hdr.type);
    buf = buf.slice(hdr.header);

    // Then comes the version field (integer). Parse it and slice it.
    pkt.version = asn1ber.parseInteger(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // We then get the community. Parse and slice.
    pkt.community = asn1ber.parseOctetString(buf.slice(0, buf[1] + 2));
    buf = buf.slice(2 + buf[1]);

    // Here's the PDU structure. We're interested in the type. Slice the rest.
    hdr = asn1ber.typeAndLength(buf);
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
    hdr = asn1ber.typeAndLength(buf);
    assert.equal(asn1ber.types.Sequence, hdr.type);
    buf = buf.slice(hdr.header);

    // Now comes the varbinds. There might be many, so we loop for as long as we have data.
    pkt.pdu.varbinds = [];
    while (buf[0] === asn1ber.types.Sequence) {
        vb = new VarBind();

        // Slice off the sequence header.
        hdr = asn1ber.typeAndLength(buf);
        assert.equal(asn1ber.types.Sequence, hdr.type);
        bvb = buf.slice(hdr.header);

        // Parse and save the ObjectIdentifier.
        vb.oid = asn1ber.parseOid(bvb);

        // Parse the value. We use the type marker to figure out
        // what kind of value it is and call the appropriate parser
        // routine. For the SNMPv2c error types, we simply set the
        // value to a text representation of the error and leave handling
        // up to the user.
        bvb = bvb.slice(2 + bvb[1]);
        vb.type = bvb[0];
        if (vb.type === asn1ber.types.Null) {
            // Null type.
            vb.value = null;
        } else if (vb.type === asn1ber.types.OctetString) {
            // Octet string type.
            vb.value = asn1ber.parseOctetString(bvb);
        } else if (vb.type === asn1ber.types.Integer ||
                   vb.type === asn1ber.types.Counter ||
                   vb.type === asn1ber.types.Counter64 ||
                   vb.type === asn1ber.types.TimeTicks ||
                   vb.type === asn1ber.types.Gauge) {
            // Integer type and it's derivatives that behave in the same manner.
            vb.value = asn1ber.parseInteger(bvb);
        } else if (vb.type === asn1ber.types.ObjectIdentifier) {
            // Object identifier type.
            vb.value = asn1ber.parseOid(bvb);
        } else if (vb.type === asn1ber.types.IpAddress) {
            // IP Address type.
            vb.value = asn1ber.parseArray(bvb);
        } else if (vb.type === asn1ber.types.Opaque) {
            // Opaque type. The 'parsing' here is very light; basically we return a
            // string representation of the raw bytes in hex.
            vb.value = asn1ber.parseOpaque(bvb);
        } else if (vb.type === asn1ber.types.EndOfMibView) {
            // End of MIB view error, returned when attempting to GetNext beyond the end
            // of the current view.
            vb.value = 'endOfMibView';
        } else if (vb.type === asn1ber.types.noSuchObject) {
            // No such object error, returned when attempting to Get/GetNext an OID that doesn't exist.
            vb.value = 'noSuchObject';
        } else if (vb.type === asn1ber.types.noSuchInstance) {
            // No such instance error, returned when attempting to Get/GetNext an instance
            // that doesn't exist in a given table.
            vb.value = 'noSuchInstance';
        } else {
            // Something else that we can't handle, so throw an error.
            // The error wull be caught and presented in a useful manner on stderr,
            // with a dump of the message causing it.
            throw new Error('Unrecognized value type ' + vb.type);
        }

        // Push whatever we parsed to the varbind list.
        pkt.pdu.varbinds.push(vb);

        // Go fetch the next varbind, if there seems to be any.
        if (buf.length > hdr.header + hdr.len) {
            buf = buf.slice(hdr.header + hdr.len);
        } else {
            break;
        }
    }

    return pkt;
}

exports.parse = parse;

// Utility functions
// -----

// Compare two OIDs, returning -1, 0 or +1 depending on the relation between
// oidA and oidB.

exports.compareOids = function (oidA, oidB) {
    var mlen, i;

    // The undefined OID, if there is any, is deemed lesser.
    if (_.isUndefined(oidA) && !_.isUndefined(oidB)) {
        return 1;
    } else if (!_.isUndefined(oidA) && _.isUndefined(oidB)) {
        return -1;
    }

    // Check each number part of the OIDs individually, and if there is any
    // position where one OID is larger than the other, return accordingly.
    // This will only check up to the minimum length of both OIDs.
    mlen = Math.min(oidA.length, oidB.length);
    for (i = 0; i < mlen; i++) {
        if (oidA[i] > oidB[i]) {
            return -1;
        } else if (oidB[i] > oidA[i]) {
            return 1;
        }
    }

    // If there is one OID that is longer than the other after the above comparison,
    // consider the shorter OID to be lesser.
    if (oidA.length > oidB.length) {
        return -1;
    } else if (oidB.length > oidA.length) {
        return 1;
    } else {
        // The OIDs are obviously equal.
        return 0;
    }
};


// Communication functions
// -----

// This is called for when we receive a message.

function msgReceived(msg, rinfo) {
    var self = this, pkt, cb, timeOut, entry;

    if (msg.length === 0) {
        // Not sure why we sometimes receive an empty message.
        // As far as I'm concerned it shouldn't happen, but we'll ignore it
        // and if it's necessary a retransmission of the request will be
        // made later.
        return;
    }

    // Parse the packet, or call the informative
    // parse error display if we fail.
    try {
        pkt = parse(msg);
    } catch (error) {
        return parseError(error, msg);
    }

    // If this message's request id matches one we've sent,
    // cancel any outstanding timeout and call the registered
    // callback.
    if (self.reqs[pkt.pdu.reqid]) {
        entry = self.reqs[pkt.pdu.reqid];
        clearTimeout(entry.timer);
        entry.cb(null, pkt);
        self.reqs[pkt.pdu.reqid] = undefined;
    } else {
        // This happens if we receive the response to a message we've already
        // send a retransmission for, for example. Maybe we shouldn't even log
        // the warning.
        console.warn('Received response message with unknown request ID ' + pkt.pdu.reqid);
    }
}

// This creates a new SNMP session. The `family` defaults to 'udp4'
// but can be set to 'udp6' to use IPv6. The family needs to match
// what is passed in `destination`.
//
function Session(destination, community, family) {
    var self = this;

    family = family || 'udp4';
    self.destination = destination;
    self.community = community;
    self.reqs = {};
    self.socket = dgram.createSocket(family);
    self.socket.on('message', _.bind(msgReceived, self));
    self.socket.on('close', function () {
        // Remove the socket so we don't try to send a message on
        // it when it's closed.
        self.socket = undefined;
    });
}

exports.Session = Session;

// Send a message. Can be used after manually constructing a correct Packet structure.

Session.prototype.sendMsg = function (pkt, callback) {
    var self = this, buf, reqid, timeOut, retrans = 0;

    // Generate a request ID. It's best kept within a signed 32 bite integer.
    reqid = parseInt(Math.random() * 65536 * 32768, 10);
    pkt.pdu.reqid = reqid;

    buf = encode(pkt);

    function transmit() {
        var entry;

        entry = self.reqs[reqid];
        if (!entry) {
            // We're in a race conditions, where the response har been received and handled but the timeout was
            // queued before that. We'll just let it slide.
            return;
        }

        if (!self.socket) {
            // The socket has already been closed, perhaps due to an error that ocurred while a timeout
            // was scheduled. We can't do anything about it now.
            return;
        }

        if (retrans > 0) {
            // Notify that we're retransmitting a packet. Only useful for debugging
            // and will probably be removed once I'm reasonably sure these mechanisms
            // work like they're supposed to.
            console.warn('Retransmit #' + retrans + ' for reqid ' + reqid + ' oid ' + pkt.pdu.varbinds[0].oid);
        }

        // Send the message. Maybe port 161 shouldn't be hard coded, but I haven't yet
        // seen a case where something else would be useful.
        self.socket.send(buf, 0, buf.length, 161, self.destination, function (err, bytes) {
            if (err) {
                callback(err);
            } else {
                if (RETRANSMISSIONS[retrans]) {
                    timeOut = setTimeout(transmit, RETRANSMISSIONS[retrans]);
                } else {
                    callback(new Error('Timeout'));
                }

                // Record the timer so that we can (attempt to) cancel it when we receive the reply.
                entry.timer = timeOut;
                retrans += 1;
            }
        });
    }

    // Register the callback to call when we receive a reply.
    self.reqs[reqid] = { cb: callback };
    // Transmit the message.
    transmit();
};

// Shortcut to create a GetRequest and send it, while registering a callback.

Session.prototype.get = function (oid, callback) {
    var self = this, pkt;

    pkt = new Packet();
    pkt.community = self.community;
    pkt.pdu.varbinds[0].oid = oid;
    self.sendMsg(pkt, callback);
};

// Shortcut to create a GetNextRequest and send it, while registering a callback.

Session.prototype.getNext = function (oid, callback) {
    var self = this, pkt;

    pkt = new Packet();
    pkt.community = self.community;
    pkt.pdu.type = 1;
    pkt.pdu.varbinds[0].oid = oid;
    self.sendMsg(pkt, callback);
};

// Close the socket. Necessary to finish the event loop and exit the program.

Session.prototype.close = function () {
    this.socket.close();
};

/*jslint onevar: true, node: true, continue: false, plusplus: false, bitwise: true,
  newcap: true, strict: false, maxerr: 50, indent: 4, undef: true */
/*globals exports: false*/
