// This file implements a minimal subset of Abstract Syntax Notation One (**ASN.1**)
// Basic Encoding Rules (**BER**), namely the parts that are necessary for sending
// and receiving SNMPv2c messages.
//
// (c) 2012 Jakob Borg, Nym Networks

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
    GetRequestPDU: 0xA0,
    GetNextRequestPDU: 0xA1,
    GetResponsePDU: 0xA2,
    SetRequestPDU: 0xA3,
    TrapPDU: 0xA4,
}

// The types are also available for consumers of the library.

exports.types = T;

// Private helper functions
// -----

// Return a wrapped copy of the passed `contents`, with the specified wrapper type.
// This is used for Sequence and other constructed types.

function wrapper(type, contents) {
    var buf;

    // Content longer than 127 bytes requires encoding the length in base 128
    // which I haven't bothered with since it's not proven necessary yet.
    if (contents.length > 127) {
        throw new Error("Can't handle content sizes larger than 127 bytes. Sorry.");
    }

    // Set up a buffer with the type and length bytes plus a straight copy of the content.
    buf = new Buffer(contents.length + 2);
    buf[0] = type;
    buf[1] = contents.length;
    contents.copy(buf, 2, 0);
    return buf;
};

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
};

// Encode an OID. The first two number are encoded specially
// in the first octet, then the rest are encoded as one octet per number
// unless the number exceeds 127. If so, it's encoded as several base-127
// octets with the high bit set to indicate continuation.

function oidArray(oid) {
    var bytes, i, val;

    // Enforce some minimum requirements on the OID.
    if (oid.length < 2) {
        throw new Error("Minimum OID length is two.");
    } else if (oid[0] !== 1 || oid[1] !== 3) {
        throw new Error("SNMP OIDs always start with .1.3.");
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

// Functions to encode ASN.1 from native objects
// -----

// Encode a simple integer.
// Integers are encoded as a simple base-256 byte sequence, most significant byte first,
// prefixed with a length byte. In principle we support arbitrary integer sizes, in practice
// Javascript doesn't even **have** integers so some precision might get lost.

exports.encodeInteger = function (val) {
    var i, buf, bytes;

    // We quickly determine the length needed for most common small integers (one or two bytes).
    // For longer sequences we make a slower calculation of the amount of bytes needed.
    if (val < 256) {
        bytes = 1;
    } else if (bytes < 65536) {
        bytes = 2;
    } else {
        bytes = Math.round(Math.log(val) / Math.log(256) + 0.5);
    }

    // Now that we know the length, we allocate a buffer of the required size.
    // We set the type and length bytes appropriately.
    buf = new Buffer(bytes + 2);
    buf[0] = T.Integer;
    buf[1] = bytes;

    // Finally we encode the integer into the buffer.
    for (i = bytes + 1; i > 1; i--) {
        buf[i] = val % 256;
        val = parseInt(val / 256, 10);
    }

    return buf;
};

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

// Encode an ObjectId.

exports.encodeOid = function (oid) {
    var buf, bytes, i;

    // Get the encoded format of the OID.
    bytes = oidArray(oid);

    // The maximum length of an OID is 128. This can indeed exceed 127 bytes in
    // encoded state, but it's unusual in practice and there are other modifications
    // needed in the code below to support those cases anyway. We'll throw an expetion
    // if this is exceeded.
    if (bytes.len > 127) {
        throw new Error('Maximum encoded size of OID exceeded. ber#oid() needs improvements to handle this case.');
    }

    // Fill in the buffer with type, length and OID data.
    buf = new Buffer(bytes.length + 2);
    buf[0] = T.ObjectIdentifier;
    buf[1] = bytes.length;
    for (i = 0; i < bytes.length; i++) {
        buf[i+2] = bytes[i];
    }

    return buf;
};

// Encode an SNMP request with specified `contents`.
// The `type` code is 0 for `GetRequest`, 1 for `GetNextRequest`.

exports.encodeRequest = function (type, contents) {
    return wrapper(T.GetRequestPDU + type, contents);
};

// Functions to parse ASN.1 to native objects
// -----

// Parse a buffer containing a representation of an integer.
// Verifies the type, then multiplies in each byte as it comes.

exports.parseInteger = function (buf) {
    var i, val;

    if (buf[0] !== T.Integer) {
        throw new Error('Buffer ' + buf.toString('hex') + ' does not appear to be an Integer');
    }

    val = 0;
    for (i = 0; i < buf[1]; i++) {
        val *= 256;
        val += buf[i+2];
    }

    return val;
};

// Parse a buffer containing a representation of an OctetString.
// Verify the type, then just grab the string out of the buffer.

exports.parseOctetString = function (buf) {
    if (buf[0] !== T.OctetString) {
        throw new Error('Buffer does not appear to be an OctetString');
    }

    // SNMP doesn't specify an encoding so I pick UTF-8 as the 'most standard'
    // encoding. We'll see if that assumption survives contact with actual reality.
    return buf.toString('utf-8', 2, 2+buf[1]);
}

// Parse a buffer containing a representation of an ObjectIdentifier.
// Verify the type, then apply the relevent encoding rules.

exports.parseOid = function (buf) {
    var oid, val, i;

    if (buf[0] !== T.ObjectIdentifier) {
        throw new Error('Buffer does not appear to be an ObjectIdentifier');
    }

    // The first byte contains the first two numbers in the OID
    oid = [ parseInt(buf[2] / 40, 10), buf[2] % 40 ];

    // The rest of the data is a base-128-encoded OID
    for (i = 0; i < buf[1] - 1; i++) {
        val = 0;
        while (buf[i + 3] > 128) {
            val += buf[i + 3] - 128;
            val *= 128;
            i++;
        }
        val += buf[i + 3];
        oid.push(val);
    }

    return oid;
}

