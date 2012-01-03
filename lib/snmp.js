var _ = require('underscore');
var der = require('./der');

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

exports.getRequest = function (version, community, reqId, oid) {
    var endB = der.null();
    var oidB = der.oid(oid);
    var varBindB = der.sequence(concatBuffers([oidB, endB]));
    var varBindListB = der.sequence(varBindB);

    var errIndexB = der.integer(0);
    var errB = der.integer(0);
    var reqIdB = der.integer(reqId);
    var pdu = der.getRequest(concatBuffers([reqIdB, errB, errIndexB, varBindListB]));

    var communityB = der.octetString(community);
    var versionB = der.integer(version);
    var messageB = der.sequence(concatBuffers([versionB, communityB, pdu]));
    return messageB;
};
