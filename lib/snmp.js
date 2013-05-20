// Introduction
// -----
// This is `node-snmp-native`, a native (Javascript) implementation of an SNMP
// client library targeted at Node.js. It's MIT licensed and available at
// https://github.com/calmh/node-snmp-native
//
// (c) 2012 Jakob Borg, Nym Networks

"use strict";

// Code
// -----
// This file implements a structure representing an SNMP message
// and routines for converting to and from the network representation.

// Define our external dependencies.
var assert = require('assert');
var dgram = require('dgram');
var events = require('events');

// We also need our ASN.1 BER en-/decoding routines.
var asn1ber = require('./asn1ber');

// Basic structures
// ----

// A `VarBind` is the innermost structure, containing an OID-Value pair.
function VarBind() {
    this.type = 5;
    this.value = null;
}

// The `PDU` contains the SNMP request or response fields and a list of `VarBinds`.
function PDU() {
    this.type = asn1ber.pduTypes.GetRequestPDU;
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
    var total, cur = 0, buf;

    // First we calculate the total length,
    total = buffers.reduce(function (tot, b) {
        return tot + b.length;
    }, 0);

    // then we allocate a new Buffer large enough to contain all data,
    buf = new Buffer(total);
    buffers.forEach(function (buffer) {
        // finally we copy the data into the new larger buffer.
        buffer.copy(buf, cur, 0);
        cur += buffer.length;
    });

    return buf;
}

// Clear a pending packet when it times out or is successfully received.

function clearRequest(reqs, reqid) {
    var self = this;

    var entry = reqs[reqid];
    if (entry) {
        if (entry.timeout) {
            clearTimeout(entry.timeout);
        }
        delete reqs[reqid];
    }
}

// Convert a string formatted OID to an array, leaving anything non-string alone.

function parseSingleOid(oid) {
    if (typeof oid !== 'string') {
        return oid;
    }

    if (oid[0] !== '.') {
        throw new Error('Invalid OID format');
    }

    oid = oid.split('.')
        .filter(function (s) {
            return s.length > 0;
        })
        .map(function (s) {
            return parseInt(s, 10);
        });

    return oid;
}

// Fix any OIDs in the 'oid' or 'oids' objects that are passed as strings.

function parseOids(options) {
    if (options.oid) {
        options.oid = parseSingleOid(options.oid);
    }
    if (options.oids) {
        options.oids = options.oids.map(parseSingleOid);
    }
}

// Update targ with attributes from _defs.
// Any existing attributes on targ are untouched.

function defaults(targ, _defs) {
    [].slice.call(arguments, 1).forEach(function (def) {
        Object.keys(def).forEach(function (key) {
            if (!targ.hasOwnProperty(key)) {
                targ[key] = def[key];
            }
        });
    });
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
    pkt.pdu.varbinds.forEach(function (vb) {
        var oid = asn1ber.encodeOid(vb.oid), val;

        if (vb.type === asn1ber.types.Null) {
            val = asn1ber.encodeNull();
        } else if (vb.type === asn1ber.types.Integer) {
            val = asn1ber.encodeInteger(vb.value);
        } else if (vb.type === asn1ber.types.Gauge) {
            val = asn1ber.encodeGauge(vb.value);
        } else if (vb.type === asn1ber.types.IpAddress) {
            val = asn1ber.encodeIpAddress(vb.value);
        } else if (vb.type === asn1ber.types.OctetString) {
            val = asn1ber.encodeOctetString(vb.value);
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
        } else if (vb.type === asn1ber.types.NoSuchObject) {
            // No such object error, returned when attempting to Get/GetNext an OID that doesn't exist.
            vb.value = 'noSuchObject';
        } else if (vb.type === asn1ber.types.NoSuchInstance) {
            // No such instance error, returned when attempting to Get/GetNext an instance
            // that doesn't exist in a given table.
            vb.value = 'noSuchInstance';
        } else {
            // Something else that we can't handle, so throw an error.
            // The error will be caught and presented in a useful manner on stderr,
            // with a dump of the message causing it.
            throw new Error('Unrecognized value type ' + vb.type);
        }

        // Take the raw octet string value and preseve it as a buffer and hex string.
        vb.valueRaw = bvb.slice(2);
        vb.valueHex = vb.valueRaw.toString('hex');

        // Add the request id to the varbind (even though it doesn't really belong)
        // so that it will be availble to the end user.
        vb.requestId = pkt.pdu.reqid;

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
    if (typeof oidA === 'undefined' && typeof oidB !== 'undefined') {
        return 1;
    } else if (typeof oidA !== 'undefined' && typeof oidB === 'undefined') {
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
    var self = this, now = Date.now(), pkt, entry;

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
        return self.parseError(error, msg);
    }

    // If this message's request id matches one we've sent,
    // cancel any outstanding timeout and call the registered
    // callback.
    entry = self.reqs[pkt.pdu.reqid];
    if (entry) {
        clearRequest(self.reqs, pkt.pdu.reqid);

        if (typeof entry.callback === 'function') {
            pkt.pdu.varbinds.forEach(function (vb) {
                vb.receiveStamp = now;
                vb.sendStamp = entry.sendStamp;
            });

            entry.callback(null, pkt.pdu.varbinds);
        }
    } else {
        // This happens if we receive the response to a message we've already timed out
        // and removed the request entry for. Maybe we shouldn't even log the warning.

        // Calculate the approximate send time and how old the packet is.
        var age = (Date.now() & 0x1fffff) - (pkt.pdu.reqid >>> 10);
        if (age < 0) {
            age += 0x200000;
        }
        console.warn('Response with unknown request ID from ' + rinfo.address + '. Consider increasing timeouts (' + age + ' ms old?).');
    }
}

// Default options for new sessions and operations.
exports.defaultOptions = {
    host: 'localhost',
    port: 161,
    community: 'public',
    family: 'udp4',
    timeouts: [ 5000, 5000, 5000, 5000 ]
};

// This creates a new SNMP session.

function Session(options) {
    var self = this;

    self.options = options || {};
    defaults(self.options, exports.defaultOptions);

    self.reqs = {};
    self.socket = dgram.createSocket(self.options.family);
    self.socket.on('message', msgReceived.bind(self));
    self.socket.on('close', function () {
        // Remove the socket so we don't try to send a message on
        // it when it's closed.
        self.socket = undefined;
    });
    self.socket.on('error', function () {
        // Errors will be emitted here as well as on the callback to the send function.
        // We handle them there, so doing anything here is unnecessary.
        // But having no error handler trips up the test suite.
    });
}

// We inherit from EventEmitter so that we can emit error events
// on fatal errors.
Session.prototype = Object.create(events.EventEmitter.prototype);
exports.Session = Session;

// Generate a request ID. It's best kept within a signed 32 bit integer.
// Uses the current time in ms, shifted left ten bits, plus a counter.
// This gives us space for 1 transmit every microsecond and wraps every
// ~1000 seconds. This is OK since we only need to keep unique ID:s for in
// flight packets and they should be safely timed out by then.

Session.prototype.requestId = function () {
    var self = this, now = Date.now();

    if (!self.prevTs) {
        self.prevTs = now;
        self.counter = 0;
    }

    if (now === self.prevTs) {
        self.counter += 1;
        if (self.counter > 1023) {
            throw new Error('Request ID counter overflow. Adjust algorithm.');
        }
    } else {
        self.prevTs = now;
        self.counter = 0;
    }

    return ((now & 0x1fffff) << 10) + self.counter;
};

// Display useful debugging information when a parse error occurs.

Session.prototype.parseError = function (error, buffer) {
    var self = this, hex;

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
    self.emit('error', error);
};

// Send a message. Can be used after manually constructing a correct Packet structure.

Session.prototype.sendMsg = function (pkt, options, callback) {
    var self = this, buf, reqid, retrans = 0;

    defaults(options, self.options);

    reqid = self.requestId();
    pkt.pdu.reqid = reqid;

    buf = encode(pkt);

    function transmit() {
        if (!self.socket || !self.reqs[reqid]) {
            // The socket has already been closed, perhaps due to an error that ocurred while a timeout
            // was scheduled. We can't do anything about it now.
            clearRequest(self.reqs, reqid);
            return;
        }

        // Send the message.
        self.socket.send(buf, 0, buf.length, options.port, options.host, function (err, bytes) {
            var entry = self.reqs[reqid];

            if (err) {
                clearRequest(self.reqs, reqid);
                return callback(err);
            } else if (entry) {
                entry.sendStamp = Date.now();

                if (options.timeouts[retrans]) {
                    // Set timeout and record the timer so that we can (attempt to) cancel it when we receive the reply.
                    entry.timeout = setTimeout(transmit, options.timeouts[retrans]);
                    retrans += 1;
                } else {
                    clearRequest(self.reqs, reqid);
                    return callback(new Error('Timeout'));
                }
            }
        });
    }

    // Register the callback to call when we receive a reply.
    self.reqs[reqid] = { callback: callback };
    // Transmit the message.
    transmit();
};

// Shortcut to create a GetRequest and send it, while registering a callback.
// Needs `options.oid` to be an OID in array form.

Session.prototype.get = function (options, callback) {
    var self = this, pkt;

    defaults(options, self.options);
    parseOids(options);

    if (!options.oid) {
        return callback(null, []);
    }

    pkt = new Packet();
    pkt.community = options.community;
    pkt.pdu.varbinds[0].oid = options.oid;
    self.sendMsg(pkt, options, callback);
};

// Shortcut to create a SetRequest and send it, while registering a callback.
// Needs `options.oid` to be an OID in array form, `options.value` to be an
// integer and `options.type` to be asn1ber.T.Integer (2).

Session.prototype.set = function (options, callback) {
    var self = this, pkt;

    defaults(options, self.options);
    parseOids(options);

    if (!options.oid) {
        throw new Error('Missing required option `oid`.');
    } else if (options.value === undefined) {
        throw new Error('Missing required option `value`.');
    } else if (!options.type) {
        throw new Error('Missing required option `type`.');
    }

    pkt = new Packet();
    pkt.community = options.community;
    pkt.pdu.type = asn1ber.pduTypes.SetRequestPDU;
    pkt.pdu.varbinds[0].oid = options.oid;
    pkt.pdu.varbinds[0].type = options.type;
    pkt.pdu.varbinds[0].value = options.value;
    self.sendMsg(pkt, options, callback);
};

// Shortcut to get all OIDs in the `options.oids` array sequentially. The
// callback is called when the entire operation is completed.  If
// options.abortOnError is truish, an error while getting any of the values
// will cause the callback to be called with error status. When
// `options.abortOnError` is falsish (the default), any errors will be ignored
// and any successfully retrieved values sent to the callback.

Session.prototype.getAll = function (options, callback) {
    var self = this, results = [];

    defaults(options, self.options, { abortOnError: false });
    parseOids(options);

    if (!options.oids || options.oids.length === 0) {
        return callback(null, []);
    }

    function getOne(c) {
        var oid, pkt, m, vb;

        pkt = new Packet();
        pkt.community = options.community;
        pkt.pdu.varbinds = [];

        // Push up to 16 varbinds in the same message.
        // The number 16 isn't really that magical, it's just a nice round
        // number that usually seems to fit withing a single packet and gets
        // accepted by the switches I've tested it on.
        for (m = 0; m < 16 && c < options.oids.length; m++) {
            vb = new VarBind();
            vb.oid = options.oids[c];
            pkt.pdu.varbinds.push(vb);
            c++;
        }

        self.sendMsg(pkt, options, function (err, varbinds) {
            if (options.abortOnError && err) {
                callback(err);
            } else {
                if (varbinds) {
                    results = results.concat(varbinds);
                }
                if (c < options.oids.length) {
                    getOne(c);
                } else {
                    callback(null, results);
                }
            }
        });
    }

    getOne(0);
};

// Shortcut to create a GetNextRequest and send it, while registering a callback.
// Needs `options.oid` to be an OID in array form.

Session.prototype.getNext = function (options, callback) {
    var self = this, pkt;

    defaults(options, self.options);
    parseOids(options);

    if (!options.oid) {
        return callback(null, []);
    }

    pkt = new Packet();
    pkt.community = options.community;
    pkt.pdu.type = 1;
    pkt.pdu.varbinds[0].oid = options.oid;
    self.sendMsg(pkt, options, callback);
};

// Shortcut to get all entries below the specified OID.
// The callback will be called once with the list of
// varbinds that was collected, or with an error object.
// Needs `options.oid` to be an OID in array form.

Session.prototype.getSubtree = function (options, callback) {
    var self = this, vbs = [];

    defaults(options, self.options);
    parseOids(options);

    if (!options.oid) {
        return callback(null, []);
    }

    options.startOid = options.oid;

    // Helper to check whether `oid` in inside the tree rooted at
    // `root` or not.
    function inTree(root, oid) {
        var i;
        if (oid.length <= root.length) {
            return false;
        }
        for (i = 0; i < root.length; i++) {
            if (oid[i] !== root[i]) {
                return false;
            }
        }
        return true;
    }

    // Helper to handle the result of getNext and call the user's callback
    // as appropriate. The callback will see one of the following patterns:
    //  - callback([an Error object], undefined) -- an error ocurred.
    //  - callback(null, [a Packet object]) -- data from under the tree.
    //  - callback(null, null) -- end of tree.
    function result(error, varbinds) {
        if (error) {
            callback(error);
        } else {
            if (inTree(options.startOid, varbinds[0].oid)) {
                if (varbinds[0].value === 'endOfMibView' || varbinds[0].value === 'noSuchObject' || varbinds[0].value === 'noSuchInstance') {
                    callback(null, vbs);
                } else {
                    vbs.push(varbinds[0]);
                    var next = { oid: varbinds[0].oid };
                    defaults(next, options);
                    self.getNext(next, result);
                }
            } else {
                callback(null, vbs);
            }
        }
    }

    self.getNext(options, result);
};

// Close the socket. Necessary to finish the event loop and exit the program.

Session.prototype.close = function () {
    this.socket.close();
};
