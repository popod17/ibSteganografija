const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

var BACKEND = 'http://localhost:8000';
var PROXY_PORT = 8001;
var PRIVATE_KEY_PATH = path.join(__dirname, 'private-key.pem');

function loadPrivateKey() {
  if (!fs.existsSync(PRIVATE_KEY_PATH)) {
    console.error('private-key.pem not found. Run: node generate-keys.js');
    process.exit(1);
  }
  return fs.readFileSync(PRIVATE_KEY_PATH, 'utf-8');
}

var passphrase = process.env.SIGN_KEY_PASS || 'stego-default-pass';
var privateKeyPem = loadPrivateKey();

var crcTable = new Uint32Array(256);
for (var n = 0; n < 256; n++) {
  var c = n;
  for (var k = 0; k < 8; k++) {
    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  }
  crcTable[n] = c;
}

function crc32(buf) {
  var crc = 0xFFFFFFFF;
  for (var i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xFF];
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function isPNG(data) {
  return data.length >= 8 &&
    data[0] === 0x89 && data[1] === 0x50 &&
    data[2] === 0x4E && data[3] === 0x47;
}

function isJPEG(data) {
  return data.length >= 2 && data[0] === 0xFF && data[1] === 0xD8;
}

function stripPNGSignature(data) {
  var offset = 8;
  var parts = [data.slice(0, 8)];
  while (offset + 8 <= data.length) {
    var length = data.readUInt32BE(offset);
    var chunkEnd = offset + 12 + length;
    if (chunkEnd > data.length) break;
    var type = data.slice(offset + 4, offset + 8).toString('ascii');
    if (type === 'tEXt') {
      var chunkData = data.slice(offset + 8, offset + 8 + length);
      var nullPos = chunkData.indexOf(0);
      if (nullPos >= 0) {
        var keyword = chunkData.slice(0, nullPos).toString('latin1');
        if (keyword === 'StegoSig') { offset = chunkEnd; continue; }
      }
    }
    parts.push(data.slice(offset, chunkEnd));
    offset = chunkEnd;
  }
  return Buffer.concat(parts);
}

function addPNGSignatureChunk(data, sigB64) {
  var offset = 8;
  var iendOffset = -1;
  while (offset + 8 <= data.length) {
    var length = data.readUInt32BE(offset);
    var chunkEnd = offset + 12 + length;
    if (chunkEnd > data.length) break;
    var type = data.slice(offset + 4, offset + 8).toString('ascii');
    if (type === 'IEND') { iendOffset = offset; break; }
    offset = chunkEnd;
  }
  if (iendOffset === -1) throw new Error('IEND not found');
  var keyword = Buffer.from('StegoSig\0', 'latin1');
  var text = Buffer.from(sigB64, 'latin1');
  var chunkData = Buffer.concat([keyword, text]);
  var typeBytes = Buffer.from('tEXt', 'ascii');
  var lengthBuf = Buffer.alloc(4);
  lengthBuf.writeUInt32BE(chunkData.length, 0);
  var crcInput = Buffer.concat([typeBytes, chunkData]);
  var crcVal = crc32(crcInput);
  var crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crcVal, 0);
  var chunk = Buffer.concat([lengthBuf, typeBytes, chunkData, crcBuf]);
  return Buffer.concat([data.slice(0, iendOffset), chunk, data.slice(iendOffset)]);
}

function stripJPEGSignature(data) {
  var offset = 2;
  var parts = [data.slice(0, 2)];
  while (offset + 4 <= data.length) {
    if (data[offset] !== 0xFF) { parts.push(data.slice(offset)); break; }
    var marker = data[offset + 1];
    if (marker === 0xDA) { parts.push(data.slice(offset)); break; }
    if (marker === 0xD8 || marker === 0xD9 ||
        (marker >= 0xD0 && marker <= 0xD7) || marker === 0x01) {
      parts.push(data.slice(offset, offset + 2));
      offset += 2; continue;
    }
    var segLength = data.readUInt16BE(offset + 2);
    var segEnd = offset + 2 + segLength;
    if (segEnd > data.length) break;
    if (marker === 0xFE) {
      var prefix = data.slice(offset + 4, offset + 4 + 9).toString('latin1');
      if (prefix === 'StegoSig:') { offset = segEnd; continue; }
    }
    parts.push(data.slice(offset, segEnd));
    offset = segEnd;
  }
  return Buffer.concat(parts);
}

function addJPEGSignatureComment(data, sigB64) {
  var payload = Buffer.from('StegoSig:' + sigB64, 'latin1');
  var segLen = payload.length + 2;
  var com = Buffer.alloc(4 + payload.length);
  com[0] = 0xFF; com[1] = 0xFE;
  com.writeUInt16BE(segLen, 2);
  payload.copy(com, 4);
  return Buffer.concat([data.slice(0, 2), com, data.slice(2)]);
}

function signBuffer(data) {
  var cleanData, addSig, fmt;
  if (isPNG(data)) {
    cleanData = stripPNGSignature(data);
    addSig = addPNGSignatureChunk;
    fmt = 'PNG';
  } else if (isJPEG(data)) {
    cleanData = stripJPEGSignature(data);
    addSig = addJPEGSignatureComment;
    fmt = 'JPEG';
  } else {
    console.log('[proxy] Not an image, passing through (' + data.length + ' bytes)');
    return data;
  }
  var timestamp = new Date().toISOString();
  var tsBuf = Buffer.from(timestamp, 'utf-8');
  var signedPayload = Buffer.concat([cleanData, tsBuf]);
  var signature = crypto.sign('sha256', signedPayload, {
    key: privateKeyPem,
    passphrase: passphrase,
    dsaEncoding: 'ieee-p1363'
  });
  var metaValue = signature.toString('base64') + '|' + timestamp;
  console.log('[proxy] Signed ' + fmt + ' (' + data.length + ' bytes) at ' + timestamp);
  return addSig(cleanData, metaValue);
}

function parseMultipart(buf, boundary) {
  var boundaryBuf = Buffer.from('--' + boundary);
  var parts = [];
  var pos = 0;

  while (pos < buf.length) {
    var bStart = buf.indexOf(boundaryBuf, pos);
    if (bStart === -1) break;
    var afterBoundary = bStart + boundaryBuf.length;
    if (buf.slice(afterBoundary, afterBoundary + 2).toString() === '--') break;
    if (buf[afterBoundary] === 0x0D && buf[afterBoundary + 1] === 0x0A) {
      afterBoundary += 2;
    } else if (buf[afterBoundary] === 0x0A) {
      afterBoundary += 1;
    }

    var headerEnd = buf.indexOf('\r\n\r\n', afterBoundary);
    var bodyStart;
    if (headerEnd === -1) {
      headerEnd = buf.indexOf('\n\n', afterBoundary);
      bodyStart = headerEnd + 2;
    } else {
      bodyStart = headerEnd + 4;
    }
    if (headerEnd === -1) break;

    var headers = buf.slice(afterBoundary, headerEnd).toString();

    var nextBoundary = buf.indexOf(boundaryBuf, bodyStart);
    if (nextBoundary === -1) nextBoundary = buf.length;

    var bodyEnd = nextBoundary;
    if (buf[bodyEnd - 2] === 0x0D && buf[bodyEnd - 1] === 0x0A) {
      bodyEnd -= 2;
    } else if (buf[bodyEnd - 1] === 0x0A) {
      bodyEnd -= 1;
    }

    parts.push({ headers: headers, body: buf.slice(bodyStart, bodyEnd) });
    pos = nextBoundary;
  }

  return parts;
}

function rebuildMultipart(parts, boundary) {
  var chunks = [];
  for (var i = 0; i < parts.length; i++) {
    chunks.push(Buffer.from('--' + boundary + '\r\n'));
    chunks.push(Buffer.from(parts[i].headers + '\r\n\r\n'));
    chunks.push(parts[i].body);
    chunks.push(Buffer.from('\r\n'));
  }
  chunks.push(Buffer.from('--' + boundary + '--\r\n'));
  return Buffer.concat(chunks);
}

function getBoundary(contentType) {
  var match = /boundary=(?:"([^"]+)"|([^\s;]+))/.exec(contentType || '');
  return match ? (match[1] || match[2]) : null;
}

function isImageContentType(headers) {
  return /filename=.*\.(png|jpg|jpeg)/i.test(headers);
}

function proxyRequest(clientReq, clientRes, body) {
  var url = new URL(clientReq.url, BACKEND);
  var headers = Object.assign({}, clientReq.headers);
  delete headers['host'];
  if (body) {
    headers['content-length'] = body.length;
  }

  var options = {
    hostname: url.hostname,
    port: url.port,
    path: url.pathname + url.search,
    method: clientReq.method,
    headers: headers
  };

  var backendReq = http.request(options, function(backendRes) {
    clientRes.writeHead(backendRes.statusCode, backendRes.headers);
    backendRes.pipe(clientRes);
  });

  backendReq.on('error', function(err) {
    clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
    clientRes.end('Proxy error: ' + err.message);
  });

  if (body) {
    backendReq.end(body);
  } else {
    clientReq.pipe(backendReq);
  }
}

var server = http.createServer(function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === 'POST' && req.url.startsWith('/upload')) {
    var chunks = [];
    req.on('data', function(chunk) { chunks.push(chunk); });
    req.on('end', function() {
      var rawBody = Buffer.concat(chunks);
      var boundary = getBoundary(req.headers['content-type']);

      if (!boundary) {
        proxyRequest(req, res, rawBody);
        return;
      }

      var parts = parseMultipart(rawBody, boundary);
      var signed = false;

      for (var i = 0; i < parts.length; i++) {
        if (isImageContentType(parts[i].headers)) {
          var fnMatch = /filename="([^"]+)"/.exec(parts[i].headers);
          var filename = fnMatch ? fnMatch[1] : 'unknown';
          console.log('[proxy] Signing file: ' + filename);
          parts[i].body = signBuffer(parts[i].body);
          signed = true;
        }
      }

      if (signed) {
        var newBody = rebuildMultipart(parts, boundary);
        req.headers['content-length'] = newBody.length;
        console.log('[proxy] Signed upload -> forwarding to backend');
        proxyRequest(req, res, newBody);
      } else {
        proxyRequest(req, res, rawBody);
      }
    });
    return;
  }

  proxyRequest(req, res, null);
});

server.listen(PROXY_PORT, function() {
  console.log('Signing proxy running on http://localhost:' + PROXY_PORT);
  console.log('Forwarding to backend at ' + BACKEND);
  console.log('Point your app API_BASE to http://localhost:' + PROXY_PORT);
});
