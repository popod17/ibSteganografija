const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

var passphrase = process.env.SIGN_KEY_PASS || 'stego-default-pass';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: passphrase
  }
});

fs.writeFileSync(path.join(__dirname, 'private-key.pem'), privateKey);

const pubKeyBase64 = publicKey
  .replace('-----BEGIN PUBLIC KEY-----', '')
  .replace('-----END PUBLIC KEY-----', '')
  .replace(/\s/g, '');

var integrityPath = path.join(__dirname, 'integrity.js');
var content = fs.readFileSync(integrityPath, 'utf-8');
content = content.replace(
  /var SIGNING_PUBLIC_KEY_B64 = '[^']*';/,
  "var SIGNING_PUBLIC_KEY_B64 = '" + pubKeyBase64 + "';"
);
fs.writeFileSync(integrityPath, content);

var sriContent = fs.readFileSync(integrityPath);
var sriHash = crypto.createHash('sha384').update(sriContent).digest('base64');
var sriValue = 'sha384-' + sriHash;

var indexPath = path.join(__dirname, 'index.html');
var indexContent = fs.readFileSync(indexPath, 'utf-8');
indexContent = indexContent.replace(
  /<script src="integrity\.js"[^>]*><\/script>/,
  '<script src="integrity.js" integrity="' + sriValue + '" crossorigin="anonymous"></script>'
);
fs.writeFileSync(indexPath, indexContent);

console.log('Key pair generated.');
console.log('  private-key.pem  (encrypted with passphrase)');
console.log('  integrity.js updated with public key.');
console.log('  index.html updated with SRI hash: ' + sriValue);
