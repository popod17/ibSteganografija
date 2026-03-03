var SIGNING_PUBLIC_KEY_B64 = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz1riGtUldED13GOCktL8OHHg3GhpDDkQCYRwOwwJBb90JCHJ0ogovqS4Vh3GzoBErR70o/DVOTZtTKRaQBLMFw==';

var ImageIntegrity = (function() {
  var _publicKey = null;

  function _getPublicKey() {
    if (_publicKey) return Promise.resolve(_publicKey);
    if (!SIGNING_PUBLIC_KEY_B64) return Promise.resolve(null);

    var binaryString = atob(SIGNING_PUBLIC_KEY_B64);
    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    return crypto.subtle.importKey(
      'spki',
      bytes.buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    ).then(function(key) {
      _publicKey = key;
      return key;
    });
  }

  function _isPNG(data) {
    return data.length >= 8 &&
      data[0] === 0x89 && data[1] === 0x50 &&
      data[2] === 0x4E && data[3] === 0x47;
  }

  function _isJPEG(data) {
    return data.length >= 2 && data[0] === 0xFF && data[1] === 0xD8;
  }

  function _parsePNG(data) {
    var SIG_KEYWORD = 'StegoSig';
    var offset = 8;
    var sigValue = null;
    var sigChunkStart = -1;
    var sigChunkEnd = -1;

    while (offset + 8 <= data.length) {
      var length = (data[offset] << 24) | (data[offset + 1] << 16) |
                   (data[offset + 2] << 8) | data[offset + 3];
      var chunkEnd = offset + 12 + length;
      if (chunkEnd > data.length) break;

      var type = String.fromCharCode(
        data[offset + 4], data[offset + 5],
        data[offset + 6], data[offset + 7]
      );

      if (type === 'tEXt') {
        var dataStart = offset + 8;
        var nullPos = dataStart;
        while (nullPos < dataStart + length && data[nullPos] !== 0) nullPos++;

        var keyword = '';
        for (var k = dataStart; k < nullPos; k++) {
          keyword += String.fromCharCode(data[k]);
        }

        if (keyword === SIG_KEYWORD) {
          var textBytes = data.slice(nullPos + 1, dataStart + length);
          sigValue = '';
          for (var t = 0; t < textBytes.length; t++) {
            sigValue += String.fromCharCode(textBytes[t]);
          }
          sigChunkStart = offset;
          sigChunkEnd = chunkEnd;
        }
      }

      offset = chunkEnd;
    }

    if (sigValue === null) {
      return { signature: null, cleanBytes: data };
    }

    var cleanBytes = new Uint8Array(data.length - (sigChunkEnd - sigChunkStart));
    cleanBytes.set(data.subarray(0, sigChunkStart), 0);
    cleanBytes.set(data.subarray(sigChunkEnd), sigChunkStart);

    return { signature: sigValue, cleanBytes: cleanBytes };
  }

  function _parseJPEG(data) {
    var SIG_PREFIX = 'StegoSig:';
    var offset = 2;
    var sigValue = null;
    var sigSegStart = -1;
    var sigSegEnd = -1;

    while (offset + 4 <= data.length) {
      if (data[offset] !== 0xFF) break;

      var marker = data[offset + 1];

      if (marker === 0xDA) break;

      if (marker === 0xD8 || marker === 0xD9 ||
          (marker >= 0xD0 && marker <= 0xD7) || marker === 0x01) {
        offset += 2;
        continue;
      }

      var segLength = (data[offset + 2] << 8) | data[offset + 3];
      var segEnd = offset + 2 + segLength;
      if (segEnd > data.length) break;

      if (marker === 0xFE) {
        var commentLen = segEnd - (offset + 4);
        var commentText = '';
        for (var c = offset + 4; c < segEnd; c++) {
          commentText += String.fromCharCode(data[c]);
        }

        if (commentText.substring(0, SIG_PREFIX.length) === SIG_PREFIX) {
          sigValue = commentText.substring(SIG_PREFIX.length);
          sigSegStart = offset;
          sigSegEnd = segEnd;
        }
      }

      offset = segEnd;
    }

    if (sigValue === null) {
      return { signature: null, cleanBytes: data };
    }

    var cleanBytes = new Uint8Array(data.length - (sigSegEnd - sigSegStart));
    cleanBytes.set(data.subarray(0, sigSegStart), 0);
    cleanBytes.set(data.subarray(sigSegEnd), sigSegStart);

    return { signature: sigValue, cleanBytes: cleanBytes };
  }

  function verify(imageBytes) {
    var data = imageBytes instanceof Uint8Array
      ? imageBytes
      : new Uint8Array(imageBytes);

    var parsed;
    if (_isPNG(data)) {
      parsed = _parsePNG(data);
    } else if (_isJPEG(data)) {
      parsed = _parseJPEG(data);
    } else {
      return Promise.resolve({ status: 'no-signature', message: 'No Signature Found \u26A0' });
    }

    if (!parsed.signature) {
      return Promise.resolve({ status: 'no-signature', message: 'No Signature Found \u26A0' });
    }

    var sigParts = parsed.signature.split('|');
    var sigB64 = sigParts[0];
    var timestamp = sigParts.length > 1 ? sigParts.slice(1).join('|') : null;

    return _getPublicKey().then(function(publicKey) {
      if (!publicKey) {
        return { status: 'no-signature', message: 'No Signature Found \u26A0' };
      }

      var sigBinary = atob(sigB64);
      var sigBytes = new Uint8Array(sigBinary.length);
      for (var i = 0; i < sigBinary.length; i++) {
        sigBytes[i] = sigBinary.charCodeAt(i);
      }

      var verifyData;
      if (timestamp) {
        var tsBytes = new TextEncoder().encode(timestamp);
        verifyData = new Uint8Array(parsed.cleanBytes.length + tsBytes.length);
        verifyData.set(parsed.cleanBytes, 0);
        verifyData.set(tsBytes, parsed.cleanBytes.length);
      } else {
        verifyData = parsed.cleanBytes;
      }

      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        sigBytes,
        verifyData
      ).then(function(valid) {
        if (valid) {
          var msg = 'Image Integrity Verified \u2705';
          if (timestamp) {
            var d = new Date(timestamp);
            if (!isNaN(d.getTime())) {
              msg += '\nSigned: ' + d.toLocaleString();
            }
          }
          return { status: 'verified', message: msg, timestamp: timestamp };
        }
        return { status: 'tampered', message: 'Image Tampered \u274C' };
      });
    }).catch(function() {
      return { status: 'tampered', message: 'Image Tampered \u274C' };
    });
  }

  return { verify: verify };
})();
