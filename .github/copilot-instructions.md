# Copilot Instructions for ibSteganografija

## Project Overview
This project is a browser-based image steganography tool supporting both LSB and DCT methods. It allows users to encode secret messages into images and upload/view them via a gallery interface. The main workflow is client-side, with optional server upload integration (API_BASE: `http://localhost:8000`).

## Key Components
- **index.html**: Main UI, modals for encoding/uploading and viewing images/messages. Integrates all JS logic and triggers workflows.
- **steganography.js**: Implements LSB steganography (PNG preferred). Provides `steg` global with `encode`, `decode`, and `getHidingCapacity` methods.
- **dct-steganography.js**: JPEG DCT coefficient steganography via `@pinta365/steganography` (loaded from esm.sh CDN). Exports `DCTSteganography` class with `embed`, `extract`, and `getCapacity` methods. Uses a 4-byte big-endian length header prepended to the message payload.
- **styles.css**: UI styling, custom fonts, modal and gallery layout.

## Developer Workflows
- **Encoding/Uploading**: Use the upload modal. For PNG, use `steg.encode`. For JPEG, use `DCTSteganography.embed` (real DCT coefficient embedding via `@pinta365/steganography`). Both produce a DataURL, which is converted to a Blob and POSTed to `/upload`.
- **Decoding/Viewing**: Gallery loads images from `/files` and `/images/{filename}`. PNG decoding uses `steg.decode`. JPEG decoding uses `DCTSteganography.extract(blob)` which operates on raw JPEG coefficient data.
- **Capacity Calculation**: Always check capacity with `steg.getHidingCapacity(img)` before encoding. UI hints update dynamically.
- **Error Handling**: All user-facing errors are shown via `setStatus` helper. JS errors are caught and displayed in modals.

## Patterns & Conventions
- **Image Handling**: Always load images as `Image` objects before encoding/decoding. Use `loadFileAsImage(file, callback)` for file inputs.
- **Format Handling**: PNG uses LSB (alpha channel); JPEG uses DCT coefficient embedding (survives JPEG re-encoding). Format is auto-detected by MIME type on upload and file extension in the viewer.
- **API Integration**: All uploads and gallery fetches use `API_BASE`. Update this if server location changes.
- **Modals**: UI actions are modal-driven. Use modal helpers for open/close logic.
- **Global State**: Minimal global variables (`uploadSourceImage`, `uploadSourceFile`, `_galleryFiles`).

## External Dependencies
- `@pinta365/steganography@0.3.2` loaded at runtime via `https://esm.sh/@pinta365/steganography@0.3.2` (dynamic `import()` in `dct-steganography.js`). Provides JPEG coefficient extraction, embedding, and re-encoding.
- `steganography.js` (LSB) is self-contained with no external dependencies.
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
```

## Key Files
- [index.html](../index.html): UI, workflow logic
- [steganography.js](../steganography.js): LSB steganography
- [dct-steganography.js](../dct-steganography.js): DCT steganography
- [styles.css](../styles.css): Styling

---
_If any workflow or pattern is unclear, please request clarification or provide feedback for improvement._
