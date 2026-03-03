# Copilot Instructions for ibSteganografija

## Project Overview
This project is a browser-based image steganography tool supporting both LSB and DCT methods. It allows users to encode secret messages into images and upload/view them via a gallery interface. All uploads pass through a local signing proxy (`http://localhost:8001`) that adds ECDSA digital signatures before forwarding to the backend (`http://localhost:8000`). The browser verifies image integrity on view using the Web Crypto API.

## Key Components
- **index.html**: Main UI, modals for encoding/uploading and viewing images/messages. Integrates all JS logic and triggers workflows. `API_BASE` points to `http://localhost:8001` (signing proxy).
- **steganography.js**: Implements LSB steganography (PNG preferred). Provides `steg` global with `encode`, `decode`, and `getHidingCapacity` methods.
- **dct-steganography.js**: JPEG DCT coefficient steganography via `@pinta365/steganography` (loaded from esm.sh CDN). Exports `DCTSteganography` class with `embed`, `extract`, and `getCapacity` methods. Uses a 4-byte big-endian length header prepended to the message payload.
- **integrity.js**: Browser-side image integrity verification. Exports `ImageIntegrity` global with a `verify(imageBytes)` method. Parses signature metadata from PNG `tEXt` chunks or JPEG `COM` markers, reconstructs the signed payload (clean bytes + timestamp), and verifies with ECDSA P-256 via Web Crypto API. Public key is embedded as base64 in `SIGNING_PUBLIC_KEY_B64`.
- **sign-proxy.js**: Node.js HTTP proxy (port 8001). Intercepts `POST /upload`, parses multipart form data, signs image bytes with ECDSA P-256 + SHA-256, embeds signature and timestamp in image metadata, then forwards to the backend. All other requests are proxied transparently. Private key is encrypted with AES-256-CBC passphrase from `SIGN_KEY_PASS` env var.
- **generate-keys.js**: Node.js script to generate an ECDSA P-256 key pair. Writes encrypted `private-key.pem`, embeds the public key in `integrity.js`, and updates the SRI hash on the `<script>` tag in `index.html`.
- **styles.css**: UI styling, custom fonts, modal and gallery layout, integrity verification badge styles.

## Architecture
```
Browser (index.html, :63342)
    │
    ├── Upload ──► Signing Proxy (:8001) ──► Backend (:8000)
    │                  │
    │                  └── Signs image with private key
    │                      Embeds signature|timestamp in metadata
    │
    └── View ──► Backend (:8000)
                    │
                    └── Browser verifies signature with public key
                        Displays: Verified ✅ | Tampered ❌ | No Signature ⚠
```

## Developer Workflows
- **Encoding/Uploading**: Use the upload modal. For PNG, use `steg.encode`. For JPEG, use `DCTSteganography.embed`. Both produce a DataURL, converted to a Blob and POSTed to `/upload` on the signing proxy (`:8001`). The proxy signs the image in-memory and forwards to the backend (`:8000`).
- **Decoding/Viewing**: Gallery loads images from `/files` and `/images/{filename}` via the proxy. PNG decoding uses `steg.decode`. JPEG decoding uses `DCTSteganography.extract(blob)`.
- **Integrity Verification**: On every image view, `ImageIntegrity.verify(arrayBuffer)` extracts the signature from metadata, strips it to get clean bytes, appends the timestamp, and verifies the ECDSA signature. Result is displayed as a badge in the viewer modal.
- **Capacity Calculation**: Always check capacity with `steg.getHidingCapacity(img)` before encoding. UI hints update dynamically.
- **Error Handling**: All user-facing errors are shown via `setStatus` helper. JS errors are caught and displayed in modals.

## Signing & Verification Details
- **Algorithm**: ECDSA with P-256 curve, SHA-256 hash, IEEE P1363 signature encoding.
- **Metadata format**: `StegoSig:<base64_signature>|<ISO_timestamp>`
  - PNG: stored in a `tEXt` chunk with keyword `StegoSig`, inserted before `IEND`.
  - JPEG: stored in a `COM` marker (0xFFFE) with prefix `StegoSig:`, inserted after SOI.
- **Signed payload**: `clean_image_bytes + timestamp_utf8_bytes`. The clean bytes are the full image with the signature metadata block removed.
- **Private key**: Encrypted with AES-256-CBC, passphrase from `SIGN_KEY_PASS` env var (default: `stego-default-pass`). Stored in `private-key.pem`, never committed to Git.
- **Public key**: Embedded as base64 SPKI in `integrity.js` variable `SIGNING_PUBLIC_KEY_B64`.
- **Replay protection**: Timestamp is included in the signed payload; verification displays the signing time.
- **SRI**: `generate-keys.js` computes SHA-384 of `integrity.js` and sets the `integrity` attribute on its `<script>` tag in `index.html`.

## Patterns & Conventions
- **Image Handling**: Always load images as `Image` objects before encoding/decoding. Use `loadFileAsImage(file, callback)` for file inputs.
- **Format Handling**: PNG uses LSB (alpha channel); JPEG uses DCT coefficient embedding. Format is auto-detected by MIME type on upload and file extension in the viewer.
- **API Integration**: All uploads and gallery fetches use `API_BASE` (`http://localhost:8001`). The proxy forwards to `http://localhost:8000`.
- **Modals**: UI actions are modal-driven. Use modal helpers for open/close logic.
- **Global State**: Minimal global variables (`uploadSourceImage`, `uploadSourceFile`, `_galleryFiles`).
- **Integrity UI**: Verification badge uses classes `viewer-integrity--verified`, `viewer-integrity--tampered`, `viewer-integrity--no-signature`, `viewer-integrity--loading`.

## Setup & Testing
```bash
# 1. Generate key pair (one-time)
set SIGN_KEY_PASS=your-passphrase
node generate-keys.js

# 2. Start backend (port 8000)
# (your existing backend)

# 3. Start signing proxy (port 8001)
set SIGN_KEY_PASS=your-passphrase
node sign-proxy.js

# 4. Open index.html in browser (port 63342 via IDE, or any server)

# Test verified: upload via browser → click image → "Image Integrity Verified ✅"
# Test no sig: upload directly to :8000 bypassing proxy → "No Signature Found ⚠"
# Test tampered: modify a signed image's bytes on disk → "Image Tampered ❌"
```

## External Dependencies
- `@pinta365/steganography@0.3.2` loaded at runtime via `https://esm.sh/@pinta365/steganography@0.3.2` (dynamic `import()` in `dct-steganography.js`). Provides JPEG coefficient extraction, embedding, and re-encoding.
- `steganography.js` (LSB) is self-contained with no external dependencies.
- `integrity.js` uses only the Web Crypto API (built into browsers).
- `sign-proxy.js` and `generate-keys.js` use only Node.js built-in modules (`crypto`, `fs`, `path`, `http`).
- Font loaded via CDN in CSS.

## Example Usage
```js
// Encode PNG (LSB, synchronous)
const dataURL = steg.encode('secret', image);
// Decode PNG
const message = steg.decode(image);
// Encode JPEG (DCT coefficients, async)
const dct = new DCTSteganography();
const jpegDataURL = await dct.embed(file, 'secret');
// Decode JPEG (accepts Blob, Uint8Array, or ArrayBuffer)
const jpegMessage = await dct.extract(blob);
// Check JPEG capacity (bytes)
const capacity = await dct.getCapacity(file);
// Verify image integrity (browser, async)
const result = await ImageIntegrity.verify(arrayBuffer);
// result = { status: 'verified'|'tampered'|'no-signature', message: '...', timestamp: '...' }
```

## Key Files
- [index.html](../index.html): UI, workflow logic
- [steganography.js](../steganography.js): LSB steganography
- [dct-steganography.js](../dct-steganography.js): DCT steganography
- [integrity.js](../integrity.js): Browser-side signature verification
- [sign-proxy.js](../sign-proxy.js): Signing proxy server
- [generate-keys.js](../generate-keys.js): Key pair generator
- [styles.css](../styles.css): Styling
- [.gitignore](../.gitignore): Excludes `private-key.pem`

---
_If any workflow or pattern is unclear, please request clarification or provide feedback for improvement._
