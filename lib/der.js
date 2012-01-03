Type = {
    SEQUENCE: 0x30,
}

exports.integer = function (val) {
    var i, buf, bytes;

    if (val < 256) {
        bytes = 1;
    } else if (bytes < 65536) {
        bytes = 2;
    } else {
        bytes = Math.round(Math.log(val) / Math.log(256) + 0.5);
    }

    buf = new Buffer(bytes + 2);
    buf[0] = 2; // Integer
    buf[1] = bytes;

    for (i = bytes + 1; i > 1; i--) {
        buf[i] = val % 256;
        val = parseInt(val / 256, 10);
    }

    return buf;
};

exports.null = function () {
    var buf = new Buffer(2);
    buf[0] = 5;
    buf[1] = 0;
    return buf;
};

function wrapper(type, contents) {
    var buf;

    if (contents.length > 127) {
        throw new Error("Can't handle content sizes larger than 127 bytes. Sorry.");
    }

    buf = new Buffer(contents.length + 2);
    buf[0] = type;
    buf[1] = contents.length;
    contents.copy(buf, 2, 0);
    return buf;
};

exports.sequence = function (contents) {
    return wrapper(0x30, contents);
};

exports.octetString = function (string) {
    var buf, contents;

    if (typeof string === 'string') {
        contents = new Buffer(string);
    } else {
        contents = string;
    }

    return wrapper(4, contents);
};

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

exports.oid = function (oid) {
    var buf, len, i, j, val, rem;

    buf = new Buffer(256);

    if (oid.length < 2) {
        throw new Error("Minimum OID length is two.");
    } else if (oid[0] !== 1 || oid[1] !== 3) {
        throw new Error("SNMP OIDs always start with .1.3.");
    }

    buf[0] = 6;
    // buf[1] will get length later
    buf[2] = 40 * oid[0] + oid[1];

    oid = oid.slice(2, oid.length);
    len = 2;
    for (i = 0; i < oid.length; i++) {
        val = oid[i];
        if (val > 127) {
            rem = oidInt(val);
            for (j = 0; j < rem.length; j++) {
                len += 1;
                buf[len] = rem[j];
            }
        } else {
            len += 1;
            buf[len] = val;
        }
    }
    buf[1] = len - 1;
    buf = buf.slice(0, len + 1);

    return buf;
};

exports.getRequest = function (contents) {
    return wrapper(160, contents);
};

