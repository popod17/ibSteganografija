# Stego Photos — Technical Documentation

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Steganography Methods](#3-steganography-methods)
   - 3.1 [LSB Steganography (PNG)](#31-lsb-steganography-png)
   - 3.2 [DCT Steganography (JPEG)](#32-dct-steganography-jpeg)
   - 3.3 [Comparison of Methods](#33-comparison-of-methods)
4. [Digital Signature & Integrity Verification](#4-digital-signature--integrity-verification)
   - 4.1 [Cryptographic Primitives](#41-cryptographic-primitives)
   - 4.2 [Key Generation](#42-key-generation)
   - 4.3 [Signing Process (Proxy)](#43-signing-process-proxy)
   - 4.4 [Signature Embedding in Metadata](#44-signature-embedding-in-metadata)
   - 4.5 [Browser-Side Verification](#45-browser-side-verification)
   - 4.6 [Subresource Integrity (SRI)](#46-subresource-integrity-sri)
5. [Security Analysis](#5-security-analysis)
   - 5.1 [Threat Model](#51-threat-model)
   - 5.2 [Attack Vectors & Mitigations](#52-attack-vectors--mitigations)
   - 5.3 [Limitations](#53-limitations)
6. [File Reference](#6-file-reference)
7. [API & Method Reference](#7-api--method-reference)
8. [Setup & Usage](#8-setup--usage)

---

## 1. Project Overview

**Stego Photos** is a browser-based image steganography gallery application. Users can:

- **Encode** secret text messages into cover images using steganographic techniques.
- **Upload** images to a backend server via a signing proxy.
- **Browse** a gallery of uploaded images.
- **Decode** hidden messages from steganographic images.
- **Verify** image integrity using ECDSA digital signatures.

The application supports two steganographic methods:

| Format | Method | Library |
|--------|--------|---------|
| PNG | Least Significant Bit (LSB) | `steganography.js` (built-in) |
| JPEG | Discrete Cosine Transform (DCT) | `@pinta365/steganography` via CDN |

All uploads are digitally signed by a local Node.js proxy before reaching the backend, enabling the browser to detect tampering.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Browser (index.html)                   │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │steganography │  │    dct-      │  │ integrity.js │   │
│  │    .js       │  │steganography │  │ (Web Crypto  │   │
│  │  (LSB/PNG)   │  │    .js       │  │   API)       │   │
│  │              │  │ (DCT/JPEG)   │  │              │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│                          │                    │          │
│           Upload (POST /upload)         Verify on view   │
└──────────────┬───────────────────────────────┬───────────┘
               │                               │
               ▼                               │
┌──────────────────────────┐                   │
│  Signing Proxy (:8001)   │                   │
│  sign-proxy.js           │                   │
│                          │                   │
│  • Intercepts uploads    │                   │
│  • Signs with ECDSA      │                   │
│  • Embeds signature in   │                   │
│    image metadata        │                   │
│  • Forwards to backend   │                   │
└──────────┬───────────────┘                   │
           │                                   │
           ▼                                   │
┌──────────────────────────┐                   │
│  Backend Server (:8000)  │◄──────────────────┘
│  (external, stores files)│    GET /images/{file}
└──────────────────────────┘    GET /files
```

**Data flow:**

1. User selects a cover image and enters a secret message.
2. Browser encodes the message into the image (LSB for PNG, DCT for JPEG).
3. Encoded image is POSTed to the signing proxy at `localhost:8001`.
4. Proxy signs the image bytes with ECDSA, embeds the signature in image metadata.
5. Proxy forwards the signed image to the backend at `localhost:8000`.
6. When viewing, the browser fetches the image, extracts the signature, and verifies it using the Web Crypto API.

---

## 3. Steganography Methods

### 3.1 LSB Steganography (PNG)

**File:** `steganography.js`  
**Global object:** `steg`  
**Author:** Peter Eigenschink (steganography.js v1.0.3)

#### How It Works

LSB (Least Significant Bit) steganography hides data in the least significant bits of pixel channel values. In this implementation, the **alpha channel** of each pixel is used as the data carrier.

##### Encoding Algorithm

1. The message string is converted to UTF-16 code units.
2. Each character's bits are split into `t`-bit bundles (default `t = 3`), meaning 3 bits of message data are encoded per pixel.
3. A prime modular arithmetic scheme is applied: for each group of pixels, the bundle values are combined using polynomial evaluation modulo the next prime ≥ $2^t$.
4. The computed values are stored in the alpha channel of the image data: `alpha = (255 - prime + 1) + (q mod prime)`.
5. After the message, a **delimiter sequence** (series of `0xFF` alpha bytes) marks the end.
6. Remaining alpha values are set to `255` (fully opaque) to clear any residual data.

##### Mathematical Detail

For parameter `t` (bits per pixel, default 3):

- Prime $p = \text{nextPrime}(2^t) = 11$ (for $t = 3$)
- Each `t`-bit bundle $b_i$ is stored as: $\alpha_i = (255 - p + 1) + (b_i \mod p) = 245 + (b_i \mod 11)$
- The message delimiter is a sequence of $3 \times \text{threshold}$ consecutive alpha values of `255`
- Decoding reverses the arithmetic: $b_i = \alpha_i - (255 - p + 1)$

##### Capacity Formula

$$\text{capacity} = \left\lfloor \frac{t \times W \times H}{\text{codeUnitSize}} \right\rfloor$$

Where:
- $t = 3$ (bits per pixel)
- $W, H$ = image width and height in pixels
- $\text{codeUnitSize} = 16$ (UTF-16)

For a 1920×1080 image: $\lfloor 3 \times 1920 \times 1080 / 16 \rfloor = 388{,}800$ characters.

##### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `t` | 3 | Bits embedded per pixel (1–7) |
| `threshold` | 1 | Polynomial evaluation threshold |
| `codeUnitSize` | 16 | Bits per character (UTF-16) |

##### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `encode` | `steg.encode(message, image, [options])` | Data URL (PNG) | Encodes message into image pixels |
| `decode` | `steg.decode(image, [options])` | String | Extracts hidden message from image |
| `getHidingCapacity` | `steg.getHidingCapacity(image, [options])` | Number | Max characters that can be hidden |

##### Usage

```js
// Check capacity
var capacity = steg.getHidingCapacity(imageElement);

// Encode
var dataURL = steg.encode("secret message", imageElement);

// Decode
var message = steg.decode(imageElement);
```

> **Note:** The `image` parameter must be an `HTMLImageElement` or a URL string. The image must be fully loaded before encoding/decoding.

---

### 3.2 DCT Steganography (JPEG)

**File:** `dct-steganography.js`  
**Class:** `DCTSteganography`  
**External library:** `@pinta365/steganography@0.3.2` (loaded from `esm.sh` CDN)

#### How It Works

DCT steganography operates on the frequency-domain coefficients of JPEG compression. Unlike LSB which modifies spatial pixel values, DCT embedding modifies the quantized DCT coefficients — the mathematical values that JPEG uses to represent 8×8 blocks of image data.

##### Encoding Algorithm

1. The JPEG file is parsed and its DCT coefficients are extracted.
2. The message is encoded as UTF-8 bytes.
3. A **4-byte big-endian length header** is prepended to the message payload.
4. The payload bytes (length + message) are embedded into the least significant bits of suitable DCT coefficients.
5. The modified coefficients are re-encoded into a valid JPEG file.

##### Payload Structure

```
┌──────────────────────┬──────────────────────────────────────┐
│  Length (4 bytes BE)  │        Message (UTF-8 bytes)         │
└──────────────────────┴──────────────────────────────────────┘
```

- **Length field:** `DataView.setUint32(0, messageBytes.length, false)` — big-endian, 4 bytes.
- **Maximum message length check:** `4 + messageBytes.length ≤ capacity`.
- **On extraction:** the length header tells the decoder exactly how many bytes to read, avoiding data corruption from trailing coefficients.

##### Capacity

Capacity depends on the number of non-zero DCT coefficients in the JPEG. This varies significantly by image content and JPEG quality:

$$\text{capacity} = \text{coefficientCount} - 4 \text{ bytes (header overhead)}$$

Typically a 1920×1080 JPEG at quality 80 has ~50,000–200,000 bytes of capacity.

##### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `embed` | `dct.embed(file, message)` | `Promise<DataURL>` | Embeds message into JPEG |
| `extract` | `dct.extract(source)` | `Promise<String>` | Extracts hidden message |
| `getCapacity` | `dct.getCapacity(file)` | `Promise<Number>` | Available bytes for hiding |

All methods are **async** since the external library is loaded dynamically.

##### Usage

```js
var dct = new DCTSteganography();

// Check capacity (bytes, not characters)
var bytes = await dct.getCapacity(fileObject);

// Embed
var dataURL = await dct.embed(fileObject, "secret message");

// Extract (accepts Blob, Uint8Array, or ArrayBuffer)
var message = await dct.extract(blob);
```

##### Library Loading

The `@pinta365/steganography` library is loaded lazily via dynamic `import()`:

```js
this._lib = await import('https://esm.sh/@pinta365/steganography@0.3.2');
```

This avoids bundling and keeps the page fast for users who don't need JPEG steganography.

---

### 3.3 Comparison of Methods

| Aspect | LSB (PNG) | DCT (JPEG) |
|--------|-----------|------------|
| **Format** | PNG (lossless) | JPEG (lossy) |
| **Domain** | Spatial (alpha pixel values) | Frequency (DCT coefficients) |
| **Channel used** | Alpha (transparency) | Quantized DCT coefficients |
| **Capacity** | High (~3 bits/pixel) | Variable (depends on content/quality) |
| **Robustness** | Fragile — any re-encoding destroys data | More resilient to minor manipulation |
| **Detection** | Detectable via alpha-channel analysis | Harder to detect statistically |
| **Sync/Async** | Synchronous | Asynchronous |
| **Dependencies** | None (self-contained) | CDN library required |
| **Message delimiter** | Bit pattern (0xFF alpha run) | 4-byte length header |

---

## 4. Digital Signature & Integrity Verification

The integrity system ensures that images uploaded through the application have not been tampered with after signing. It uses an asymmetric cryptographic scheme where:

- A **private key** (stored only on the signing server) creates signatures.
- A **public key** (embedded in the browser code) verifies signatures.
- Even if an attacker intercepts the image, they cannot forge a valid signature without the private key.

### 4.1 Cryptographic Primitives

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key pair | ECDSA with P-256 (secp256r1) curve | FIPS 186-4 / SEC 2 |
| Hash function | SHA-256 | FIPS 180-4 |
| Signature encoding | IEEE P1363 (raw r‖s) | IEEE P1363 |
| Key format (public) | SPKI DER, base64-encoded | RFC 5480 |
| Key format (private) | PKCS#8 PEM, AES-256-CBC encrypted | RFC 5958, RFC 5652 |
| Browser verification | Web Crypto API | W3C Web Cryptography API |
| Script protection | Subresource Integrity (SHA-384) | W3C SRI |

#### Why ECDSA P-256?

- **Compact signatures:** 64 bytes (IEEE P1363), vs 256+ bytes for RSA-2048.
- **Web Crypto native:** Supported in all modern browsers without polyfills.
- **Node.js native:** Built into `crypto` module, no external dependencies.
- **Equivalent security:** P-256 provides ~128-bit security level, comparable to RSA-3072.

#### Why IEEE P1363 encoding?

The Web Crypto API requires IEEE P1363 format for ECDSA signatures (raw concatenation of `r` and `s` values, each 32 bytes for P-256). Node.js defaults to DER encoding, so we explicitly set `dsaEncoding: 'ieee-p1363'` when signing.

### 4.2 Key Generation

**File:** `generate-keys.js`

The key generation script performs three tasks:

1. **Generates an ECDSA P-256 key pair** using `crypto.generateKeyPairSync()`.
2. **Encrypts the private key** with AES-256-CBC, using a passphrase from the `SIGN_KEY_PASS` environment variable.
3. **Embeds the public key** into `integrity.js` (as base64 SPKI) and computes the SRI hash for `index.html`.

```
generate-keys.js
       │
       ├──► private-key.pem      (encrypted PKCS#8 PEM, AES-256-CBC)
       ├──► integrity.js         (public key injected into SIGNING_PUBLIC_KEY_B64)
       └──► index.html           (SRI hash updated on <script> tag)
```

#### Private Key Encryption

The private key is **never** stored in plaintext. It is encrypted with AES-256-CBC:

```js
privateKeyEncoding: {
  type: 'pkcs8',
  format: 'pem',
  cipher: 'aes-256-cbc',
  passphrase: process.env.SIGN_KEY_PASS || 'stego-default-pass'
}
```

The encrypted PEM file looks like:

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgXXXX...
...
-----END ENCRYPTED PRIVATE KEY-----
```

The same passphrase must be provided to `sign-proxy.js` at runtime to decrypt the key.

### 4.3 Signing Process (Proxy)

**File:** `sign-proxy.js`

The signing proxy is a Node.js HTTP server on port 8001 that transparently proxies all requests to the backend on port 8000, except for `POST /upload` — which it intercepts to sign image files.

#### Signing Flow

```
1. Browser POSTs multipart/form-data to :8001/upload
2. Proxy parses multipart body, finds image parts
3. For each image:
   a. Strip any existing signature metadata (idempotent re-signing)
   b. Get clean image bytes
   c. Generate ISO-8601 timestamp
   d. Compute: signedPayload = cleanBytes + timestampBytes
   e. ECDSA-sign the payload with the encrypted private key
   f. Embed "base64(signature)|timestamp" in image metadata
4. Rebuild multipart body with signed image(s)
5. Forward to backend at :8000
```

#### `signBuffer(data)` — Core Signing Function

```js
function signBuffer(data) {
  // 1. Detect format
  if (isPNG(data)) { /* ... */ }
  else if (isJPEG(data)) { /* ... */ }
  else { return data; } // pass through non-images

  // 2. Strip existing signature (idempotent)
  var cleanData = stripSignature(data);

  // 3. Create timestamp
  var timestamp = new Date().toISOString();
  var tsBuf = Buffer.from(timestamp, 'utf-8');

  // 4. Build signed payload: clean image + timestamp
  var signedPayload = Buffer.concat([cleanData, tsBuf]);

  // 5. Sign with ECDSA P-256
  var signature = crypto.sign('sha256', signedPayload, {
    key: privateKeyPem,
    passphrase: passphrase,
    dsaEncoding: 'ieee-p1363'
  });

  // 6. Embed metadata
  var metaValue = signature.toString('base64') + '|' + timestamp;
  return addSignatureMetadata(cleanData, metaValue);
}
```

#### Multipart Parsing

The proxy includes a custom multipart/form-data parser:

- **`parseMultipart(buf, boundary)`** — Splits the raw body into parts, each with `headers` (string) and `body` (Buffer).
- **`rebuildMultipart(parts, boundary)`** — Reassembles parts into a valid multipart body.
- **`getBoundary(contentType)`** — Extracts the boundary string from the Content-Type header.

Image parts are identified by checking `filename=.*\.(png|jpg|jpeg)` in the part headers.

### 4.4 Signature Embedding in Metadata

Signatures are embedded **inside the image file** using format-specific metadata containers that survive normal file transfer and storage.

#### Metadata Format

```
StegoSig:<base64_signature>|<ISO_8601_timestamp>
```

Example:
```
StegoSig:MEUCIHra...base64...==|2026-03-03T14:22:01.123Z
```

#### PNG: `tEXt` Chunk

PNG files consist of chunks. A `tEXt` chunk stores a keyword-value pair:

```
┌────────────┬────────────┬──────────────────────────┬──────────┐
│ Length (4B) │ "tEXt" (4B)│ Data (keyword\0value)    │ CRC (4B) │
└────────────┴────────────┴──────────────────────────┴──────────┘
```

- **Keyword:** `StegoSig` (followed by null byte `\0`)
- **Value:** `<base64_signature>|<timestamp>`
- **Position:** Inserted immediately before the `IEND` chunk (last chunk in PNG)

The CRC-32 is computed over the type + data bytes per the PNG specification.

##### Stripping (for re-signing or verification)

To obtain clean bytes, the proxy/verifier scans all `tEXt` chunks and removes any with keyword `StegoSig`. The remaining bytes form the clean image.

#### JPEG: `COM` Marker

JPEG files consist of segments prefixed by markers. The `COM` (comment) marker `0xFFFE` stores arbitrary text:

```
┌──────────┬────────────┬──────────────────────────────────┐
│ FF FE    │ Length (2B) │ "StegoSig:" + sig + "|" + ts     │
│ (marker) │ (includes  │                                  │
│          │  itself)   │                                  │
└──────────┴────────────┴──────────────────────────────────┘
```

- **Prefix:** `StegoSig:` (9 ASCII bytes)
- **Value:** `<base64_signature>|<timestamp>`
- **Position:** Inserted immediately after the SOI marker (`0xFFD8`, first 2 bytes)

##### Stripping

The parser scans JPEG segments. Any `COM` marker whose payload starts with `StegoSig:` is removed. Scanning stops at the SOS marker (`0xFFDA`), after which the entropy-coded data begins.

### 4.5 Browser-Side Verification

**File:** `integrity.js`  
**Global object:** `ImageIntegrity`

The browser verifies image integrity using the Web Crypto API — no server round-trip needed.

#### Verification Flow

```
1. Receive image as ArrayBuffer
2. Detect format (PNG magic bytes / JPEG SOI marker)
3. Parse metadata to extract signature string
4. Split: base64Signature | timestamp
5. Strip signature metadata to get cleanBytes
6. Reconstruct verifyData = cleanBytes + encode(timestamp)
7. Import public key (SPKI, base64 → ArrayBuffer → CryptoKey)
8. crypto.subtle.verify('ECDSA', publicKey, signatureBytes, verifyData)
9. Return result: verified ✅ | tampered ❌ | no-signature ⚠
```

#### `ImageIntegrity.verify(imageBytes)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `imageBytes` | `ArrayBuffer` or `Uint8Array` | Raw image file bytes |

**Returns:** `Promise<{ status, message, timestamp }>`

| status | Meaning |
|--------|---------|
| `'verified'` | Signature is valid — image is authentic |
| `'tampered'` | Signature is invalid — image was modified |
| `'no-signature'` | No signature found — image was not signed |

#### Public Key Loading

The public key is embedded as a base64-encoded SPKI blob in `SIGNING_PUBLIC_KEY_B64`. On first use, it is decoded and imported as a `CryptoKey`:

```js
crypto.subtle.importKey(
  'spki',
  spkiArrayBuffer,
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,        // not extractable
  ['verify']    // usage: verification only
)
```

The imported key is cached in memory for subsequent verifications.

### 4.6 Subresource Integrity (SRI)

To prevent tampering with `integrity.js` itself (which contains the public key), the `<script>` tag includes an SRI hash:

```html
<script src="integrity.js"
        integrity="sha384-XXXXX..."
        crossorigin="anonymous"></script>
```

If the file has been modified, the browser will refuse to execute it. The SHA-384 hash is automatically computed and injected by `generate-keys.js` whenever keys are regenerated.

---

## 5. Security Analysis

### 5.1 Threat Model

The system protects against:

1. **Man-in-the-Middle (MITM) modification** — An attacker intercepting and modifying images in transit between server and browser.
2. **Server-side tampering** — An attacker who gains write access to the backend storage and modifies image files.
3. **Replay attacks** — An attacker re-using an old signed image.
4. **Integrity script tampering** — An attacker modifying the verification code to always return "verified".

The system does **not** protect against:

- Compromise of the signing machine (where the private key resides).
- An attacker who can modify `index.html` to remove the SRI attribute.

### 5.2 Attack Vectors & Mitigations

| Attack | Vector | Mitigation | Residual Risk |
|--------|--------|-----------|---------------|
| **Image modification** | Attacker changes pixel data | ECDSA signature covers all clean image bytes; any modification invalidates the signature | None if keys are secure |
| **Signature forgery** | Attacker creates a fake signature | Requires private key (256-bit ECDSA); computationally infeasible (~$2^{128}$ operations) | None with current crypto |
| **Replay attack** | Attacker re-uploads old signed image | ISO-8601 timestamp included in signed payload; UI shows signing time to the user | User must check the timestamp |
| **Metadata stripping** | Attacker removes the signature | Verification returns "No Signature Found ⚠"; obvious to user | User relies on UI indicator |
| **Key extraction** | Attacker reads private-key.pem | Key is AES-256-CBC encrypted with passphrase; `.gitignore` excludes from repository | Passphrase weakness |
| **Public key replacement** | Attacker substitutes their own key in integrity.js | SRI hash on `<script>` tag; browser blocks execution if hash mismatches | Attacker modifying index.html |
| **Verification bypass** | Attacker modifies integrity.js to always return "verified" | SRI hash protects the script contents | Attacker modifying index.html |

### 5.3 Limitations

1. **No HTTPS in development:** The current setup uses plain HTTP. In production, HTTPS (TLS) should wrap all communication to prevent active MITM attacks on the HTML itself.

2. **Default passphrase:** If `SIGN_KEY_PASS` is not set, the fallback `stego-default-pass` is used. This should always be overridden in real deployments.

3. **No certificate authority:** The public key is self-managed. There is no revocation mechanism — if the private key is compromised, a new key pair must be generated and all previously signed images become unverifiable with the new key.

4. **Timestamp is not verified against a trusted clock:** The timestamp is generated by the signing proxy's system clock. An attacker with access to the proxy could set the clock to any value.

5. **SRI requires CORS:** The `crossorigin="anonymous"` attribute on the script tag requires the server to send proper CORS headers. Some IDE dev servers may not support this.

6. **Hidden message is not part of the signature:** The steganographic content is embedded *before* signing, so it is included in the signed bytes. However, the signature does not authenticate the *intent* to hide a specific message — it only proves the image bytes are unchanged.

---

## 6. File Reference

| File | Type | Purpose |
|------|------|---------|
| `index.html` | HTML | Main UI — gallery, upload modal, viewer modal, all JavaScript logic |
| `steganography.js` | JS (browser) | LSB steganography library for PNG images |
| `dct-steganography.js` | JS (browser) | DCT coefficient steganography wrapper for JPEG images |
| `integrity.js` | JS (browser) | Signature verification using Web Crypto API; contains embedded public key |
| `sign-proxy.js` | JS (Node.js) | HTTP signing proxy — intercepts uploads, signs images, forwards to backend |
| `generate-keys.js` | JS (Node.js) | One-time key pair generation; updates integrity.js and index.html |
| `styles.css` | CSS | All styling — layout, gallery grid, modals, integrity badges |
| `private-key.pem` | PEM | Encrypted ECDSA private key (generated, git-ignored) |
| `.gitignore` | Config | Excludes private-key.pem, .github/, .idea/ |

---

## 7. API & Method Reference

### `steg` — LSB Steganography (Global)

```js
// Encode a message into an image
// Returns: data URL string (image/png)
steg.encode(message: string, image: HTMLImageElement | string, options?: object): string

// Decode a message from an image
// Returns: hidden message string
steg.decode(image: HTMLImageElement | string, options?: object): string

// Get maximum characters that can be hidden
// Returns: integer
steg.getHidingCapacity(image: HTMLImageElement, options?: object): number
```

### `DCTSteganography` — DCT Steganography (Class)

```js
var dct = new DCTSteganography();

// Embed a message into a JPEG file
// Returns: Promise resolving to a data URL string (image/jpeg)
await dct.embed(imageFile: File, message: string): Promise<string>

// Extract a hidden message from a JPEG source
// Returns: Promise resolving to the message string (or '' if none)
await dct.extract(source: Blob | Uint8Array | ArrayBuffer): Promise<string>

// Get available capacity in bytes
// Returns: Promise resolving to an integer (bytes, minus 4-byte header)
await dct.getCapacity(imageFile: File): Promise<number>
```

### `ImageIntegrity` — Signature Verification (Global)

```js
// Verify image integrity
// Returns: Promise<{ status: string, message: string, timestamp?: string }>
// status: 'verified' | 'tampered' | 'no-signature'
await ImageIntegrity.verify(imageBytes: ArrayBuffer | Uint8Array): Promise<object>
```

### `sign-proxy.js` — Internal Functions

| Function | Description |
|----------|-------------|
| `loadPrivateKey()` | Reads `private-key.pem` from disk; exits if missing |
| `crc32(buf)` | Computes CRC-32 for PNG chunk validation |
| `isPNG(data)` / `isJPEG(data)` | Format detection via magic bytes |
| `stripPNGSignature(data)` | Removes `StegoSig` tEXt chunk from PNG |
| `stripJPEGSignature(data)` | Removes `StegoSig:` COM segment from JPEG |
| `addPNGSignatureChunk(data, sigB64)` | Inserts tEXt chunk with signature before IEND |
| `addJPEGSignatureComment(data, sigB64)` | Inserts COM segment with signature after SOI |
| `signBuffer(data)` | Full sign pipeline: detect → strip → sign → embed |
| `parseMultipart(buf, boundary)` | Splits multipart/form-data into parts |
| `rebuildMultipart(parts, boundary)` | Rejoins parts into multipart body |
| `getBoundary(contentType)` | Extracts boundary from Content-Type header |
| `proxyRequest(req, res, body)` | Forwards a request to the backend |

### `generate-keys.js` — Key Generation

| Step | Action |
|------|--------|
| 1 | Generate ECDSA P-256 key pair with `crypto.generateKeyPairSync` |
| 2 | Encrypt private key with AES-256-CBC (passphrase from `SIGN_KEY_PASS` env) |
| 3 | Write `private-key.pem` |
| 4 | Extract base64 SPKI public key, inject into `integrity.js` |
| 5 | Compute SHA-384 hash of `integrity.js`, update SRI in `index.html` |

### UI Functions (index.html)

| Function | Description |
|----------|-------------|
| `openUploadModal()` / `closeUploadModal()` | Toggle the encode & upload modal |
| `openPlainUploadModal()` / `closePlainUploadModal()` | Toggle the plain upload modal |
| `uploadImage()` | Encode message into image, then upload to proxy |
| `plainUploadImage()` | Upload an image without encoding a message |
| `openViewer(filename, showMessage)` | Open the image viewer; triggers integrity verification |
| `closeViewer()` | Close the viewer modal |
| `loadGallery()` | Fetch file list from server, update gallery grid with smart diff |
| `handleFabClick(e)` | FAB button: click = plain upload, Ctrl+click = encode & upload |
| `setStatus(id, msg, type)` | Display status messages (info/success/error) |
| `loadFileAsImage(file, callback)` | Convert a File to an HTMLImageElement via FileReader |
| `showDecodedMessage(msgEl, message)` | Display decoded message in the viewer |

---

## 8. Setup & Usage

### Prerequisites

- **Node.js** (v16+ recommended) — for the signing proxy and key generation
- **Backend server** running on `localhost:8000` — accepts `POST /upload` (multipart/form-data) and serves `GET /files`, `GET /images/{filename}`
- **Modern browser** — Chrome, Firefox, Edge, Safari (Web Crypto API required)

### Step 1: Generate Keys

```bash
# Set your passphrase (use a strong one in production)
set SIGN_KEY_PASS=your-strong-passphrase

# Generate key pair
node generate-keys.js
```

This creates `private-key.pem`, updates the public key in `integrity.js`, and updates the SRI hash in `index.html`.

### Step 2: Start the Backend

Start your backend server on port 8000 (implementation-specific).

### Step 3: Start the Signing Proxy

```bash
# Same passphrase as key generation
set SIGN_KEY_PASS=your-strong-passphrase

node sign-proxy.js
```

Output:
```
Signing proxy running on http://localhost:8001
Forwarding to backend at http://localhost:8000
Point your app API_BASE to http://localhost:8001
```

### Step 4: Open the Application

Open `index.html` in your browser (e.g., via IDE live server on port 63342, or any static file server). The `API_BASE` in the script is set to `http://localhost:8001`.

### Testing Scenarios

| Scenario | Steps | Expected Result |
|----------|-------|-----------------|
| **Verified** ✅ | Upload via browser (through proxy) → click image to view | "Image Integrity Verified ✅" with signing timestamp |
| **No Signature** ⚠ | Upload directly to `:8000` bypassing proxy | "No Signature Found ⚠" |
| **Tampered** ❌ | Modify a signed image's bytes on disk → view in browser | "Image Tampered ❌" |

### UI Interaction

- **Click `+` button** → Opens plain upload modal
- **Ctrl + click `+` button** → Opens encode & upload modal (steganography)
- **Click a gallery image** → Opens viewer with integrity badge
- **Ctrl + click a gallery image** → Opens viewer **and** decodes hidden message
