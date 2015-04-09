// This file implements a minimal subset of Abstract Syntax Notation One (**ASN.1**)
// Basic Encoding Rules (**BER**), namely the parts that are necessary for sending
// and receiving SNMPv2c messages.
//
// (c) 2012 Jakob Borg, Nym Networks

"use strict";

// We define constants for the commonly used ASN.1 types in SNMP.

var T = {
    Integer: 0x02,
    OctetString: 0x04,
    Null: 0x05,
    ObjectIdentifier: 0x06,
    Sequence: 0x30,
    IpAddress: 0x40,
    Counter: 0x41,
    Gauge: 0x42,
    TimeTicks: 0x43,
    Opaque: 0x44,
    NsapAddress: 0x45,
    Counter64: 0x46,
    NoSuchObject: 0x80,
    NoSuchInstance: 0x81,
    EndOfMibView: 0x82,
    PDUBase: 0xA0
};

var P = {
    GetRequestPDU: 0x00,
    GetNextRequestPDU: 0x01,
    GetResponsePDU: 0x02,
    SetRequestPDU: 0x03
};

var E = {
    NoError: 0,
    TooBig: 1,
    NoSuchName: 2,
    BadValue: 3,
    ReadOnly: 4,
    GenErr: 5
};

var LOG256 = Math.log(256);

// The types are also available for consumers of the library.

exports.types = T;
exports.pduTypes = P;
exports.errors = E;
exports.unittest = {};

// Private helper functions
// -----

// Encode a length as it should be encoded.

function lengthArray(len) {
    var arr = [];

    if (len <= 127) {
        // Return a single byte if the value is 127 or less.
        return [ len ];
    } else {
        // Otherwise encode it as a MSB base-256 integer.
        while (len > 0) {
            arr.push(len % 256);
            len = parseInt(len / 256, 10);
        }
        // Add a length byte in front and set the high bit to indicate
        // that this is a longer value than one byte.
        arr.push(128 + arr.length);
        arr.reverse();
        return arr;
    }
}

exports.unittest.lengthArray = lengthArray;

// Return a wrapped copy of the passed `contents`, with the specified wrapper type.
// This is used for Sequence and other constructed types.

function wrapper(type, contents) {
    var buf, len, i;

    // Get the encoded length of the contents
    len = lengthArray(contents.length);

    // Set up a buffer with the type and length bytes plus a straight copy of the content.
    buf = new Buffer(1 + contents.length + len.length);
    buf[0] = type;
    for (i = 1; i < len.length + 1; i++) {
        buf[i] = len[i - 1];
    }
    contents.copy(buf, len.length + 1, 0);
    return buf;
}

// Get the encoded representation of a number in an OID.
// If the number is less than 128, pass it as it is.
// Otherwise return an array of base-128 digits, most significant first,
// with the high bit set on all octets except the last one.
// This encoding should be used for all number in an OID except the first
// two (.1.3) which are handled specially.

function oidInt(val) {
    var bytes = [];

    bytes.push(val % 128);
    val = parseInt(val / 128, 10);
    while (val > 127) {
        bytes.push(128 + val % 128);
        val = parseInt(val / 128, 10);
    }
    bytes.push(val + 128);
    return bytes.reverse();
}

// Encode an OID. The first two number are encoded specially
// in the first octet, then the rest are encoded as one octet per number
// unless the number exceeds 127. If so, it's encoded as several base-127
// octets with the high bit set to indicate continuation.
function oidArray(oid) {
    var bytes, i, val;

    // Enforce some minimum requirements on the OID.
    if (oid.length < 2) {
        throw new Error("Minimum OID length is two.");
    } else if (oid[0] > 2) {
        throw new Error("Invalid OID");
    } else if (oid[0] == 0 && oid[1] > 39) {
        throw new Error("Invalid OID");
    } else if (oid[0] == 1 && oid[1] > 39) {
        throw new Error("Invalid OID");
    } else if (oid[0] == 2 && oid[1] > 79) {
        throw new Error("Invalid OID");
    }

    // Calculate the first byte of the encoded OID according to the 'special' rule.
    bytes = [ 40 * oid[0] + oid[1] ];

    // For the rest of the OID, encode each number individually and add the
    // resulting bytes to the buffer.
    for (i = 2; i < oid.length; i++) {
        val = oid[i];
        if (val > 127) {
            bytes = bytes.concat(oidInt(val));
        } else {
            bytes.push(val);
        }
    }

    return bytes;
}

// Divide an integer into base-256 bytes.
// Most significant byte first.
function intArray(val) {
    var array = [], encVal = val, bytes;

    if (val === 0) {
        array.push(0);
    } else {
        if (val < 0) {
            bytes = Math.floor(1 + Math.log(-val) / LOG256)
            // Encode negatives as 32-bit two's complement. Let's hope that fits.
            encVal += Math.pow(2, 8 * bytes);
        }
        while (encVal > 0) {
            array.push(encVal % 256);
            encVal = parseInt(encVal / 256, 10);
        }
    }

    // Do not produce integers that look negative (high bit
    // of first byte set).
    if (val > 0 && array[array.length - 1] >= 0x80) {
        array.push(0);
    }

    return array.reverse();
}

// Functions to encode ASN.1 from native objects
// -----

// Encode a simple integer.
// Integers are encoded as a simple base-256 byte sequence, most significant byte first,
// prefixed with a length byte. In principle we support arbitrary integer sizes, in practice
// Javascript doesn't even **have** integers so some precision might get lost.

function encodeIntegerish(val, type) {
    var i, arr, buf;

    // Get the bytes that we're going to encode.
    arr = intArray(val);

    // Now that we know the length, we allocate a buffer of the required size.
    // We set the type and length bytes appropriately.
    buf = new Buffer(2 + arr.length);
    buf[0] = type;
    buf[1] = arr.length;

    // Copy the bytes into the array.
    for (i = 0; i < arr.length; i++) {
        buf[i + 2] = arr[i];
    }

    return buf;
};

// Integer type, 0x02
exports.encodeInteger = function (val) {
    return(encodeIntegerish(val, T.Integer));
}

// Gauge type, 0x42
exports.encodeGauge = function (val) {
    return(encodeIntegerish(val, T.Gauge));
}

// Counter type, 0x41
exports.encodeCounter = function (val) {
    return(encodeIntegerish(val, T.Counter));
}

// TimeTicks type, 0x43
exports.encodeTimeTicks = function (val) {
    return(encodeIntegerish(val, T.TimeTicks));
}

// Create the representation of a Null, `05 00`.

exports.encodeNull = function () {
    var buf = new Buffer(2);
    buf[0] = T.Null;
    buf[1] = 0;
    return buf;
};

// Encode a Sequence, which is a wrapper of type `30`.

exports.encodeSequence = function (contents) {
    return wrapper(T.Sequence, contents);
};

// Encode an OctetString, which is a wrapper of type `04`.

exports.encodeOctetString = function (string) {
    var buf, contents;

    if (typeof string === 'string') {
        contents = new Buffer(string);
    } else if (Buffer.isBuffer(string)) {
        contents = string;
    } else {
        throw new Error('Only Buffer and string types are acceptable as OctetString.');
    }

    return wrapper(T.OctetString, contents);
};

// Encode an IpAddress, which is a wrapper of type `40`.

exports.encodeIpAddress = function (address) {
    var contents, octets, value = [];

    if (typeof address !== 'string' && !Buffer.isBuffer(address)) {
        throw new Error('Only Buffer and string types are acceptable as OctetString.');
    }

    // assume that the string is in dotted decimal format ipv4
    // also, use toString in case a buffer was passed in.

    octets = address.toString().split('.');
    if (octets.length !== 4) {
        throw new Error('IP Addresses must be specified in dotted decimal format.');
    }
    octets.forEach(function (octet) {
        var octetValue = parseInt(octet, 10);
        if (octet < 0 || octet > 255) {
            throw new Error('IP Address octets must be between 0 and 255 inclusive.' + JSON.stringify(octets));
        }
        value.push(octetValue);
    });

    contents = new Buffer(value);

    return wrapper(T.IpAddress, contents);
};

// Encode an ObjectId.

exports.encodeOid = function (oid) {
    var buf, bytes, i, len;

    // Get the encoded format of the OID.
    bytes = oidArray(oid);

    // Get the encoded format of the length
    len = lengthArray(bytes.length);

    // Fill in the buffer with type, length and OID data.
    buf = new Buffer(1 + bytes.length + len.length);
    buf[0] = T.ObjectIdentifier;
    for (i = 1; i < len.length + 1; i++) {
        buf[i] = len[i - 1];
    }
    for (i = len.length + 1; i < bytes.length + len.length + 1; i++) {
        buf[i] = bytes[i - len.length - 1];
    }

    return buf;
};

// Encode an SNMP request with specified `contents`.
// The `type` code is 0 for `GetRequest`, 1 for `GetNextRequest`.

exports.encodeRequest = function (type, contents) {
    return wrapper(T.PDUBase + type, contents);
};

// Functions to parse ASN.1 to native objects
// -----

// Parse and return type, data length and header length.
function typeAndLength(buf) {
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
            res.len *= 256;
            res.len += buf[i + 2];
        }
        res.header += buf[1] - 128 + 1;
    }
    return res;
}

exports.typeAndLength = typeAndLength;

// Parse a buffer containing a representation of an integer.
// Verifies the type, then multiplies in each byte as it comes.

exports.parseInteger = function (buf) {
    var i, val, type, len;

    type = buf[0];
    len = buf[1];

    if (type !== T.Integer && type !== T.Counter &&
        type !== T.Counter64 && type !== T.Gauge &&
        type !== T.TimeTicks) {
        throw new Error('Buffer ' + buf.toString('hex') + ' does not appear to be an Integer');
    }

    val = 0;
    for (i = 0; i < len; i++) {
        val *= 256;
        val += buf[i + 2];
    }

    if (buf[2] > 127 && type === T.Integer) {
        return val - Math.pow(2, 8 * buf[1]);
    } else {
        return val;
    }
};

// Parse a buffer containing a representation of an OctetString.
// Verify the type, then just grab the string out of the buffer.

exports.parseOctetString = function (buf) {
    var i, len, lenBytes = 0;

    if (buf[0] !== T.OctetString) {
        throw new Error('Buffer does not appear to be an OctetString');
    }

    // SNMP doesn't specify an encoding so I pick UTF-8 as the 'most standard'
    // encoding. We'll see if that assumption survives contact with actual reality.

    var len = buf[1];
    if (len > 128) {
        // Multi byte length encoding
        lenBytes = len - 128;
        len = 0;
        for (i = 0; i < lenBytes; i++) {
            len *= 256
            len += buf[2+i]
        }
    }
    return buf.toString('utf-8', 2 + lenBytes, 2 + lenBytes + len);
};

// Parse a buffer containing a representation of an ObjectIdentifier.
// Verify the type, then apply the relevent encoding rules.

exports.parseOid = function (buf) {
    var oid, val, i, o1, o2;

    if (buf[0] !== T.ObjectIdentifier) {
        throw new Error('Buffer does not appear to be an ObjectIdentifier');
    }

    // The first byte contains the first two numbers in the OID. They're
    // magical! They're compactly encoded in a special way! KILL ME NOW!
    o1 = parseInt(buf[2] / 40, 10);
    if (o1 > 2) {
        o1 = 2;
    }
    o2 = buf[2] - 40 * o1;
    oid = [o1, o2];

    // The rest of the data is a base-128-encoded OID
    for (i = 0; i < buf[1] - 1; i++) {
        val = 0;
        while (buf[i + 3] >= 128) {
            val += buf[i + 3] - 128;
            val *= 128;
            i++;
        }
        val += buf[i + 3];
        oid.push(val);
    }

    return oid;
};

// Parse a buffer containing a representation of an array type.
// This is for example an IpAddress.

exports.parseArray = function (buf) {
    var i, nelem, array;

    if (buf[0] !== T.IpAddress) {
        throw new Error('Buffer does not appear to be an array type.');
    }

    nelem = buf[1];
    array = [];

    for (i = 0; i < buf[1]; i++) {
        array.push(buf[i + 2]);
    }

    return array;
};

// Parse a buffer containing a representation of an opaque type.
// This is for example an IpAddress.

exports.parseOpaque = function (buf) {
    var hdr;

    hdr = typeAndLength(buf);

    if (hdr.type !== T.Opaque) {
        throw new Error('Buffer does not appear to be an opaque type.');
    }

    return '0x' + buf.slice(hdr.header).toString('hex');
};

/*globals exports: false*/
