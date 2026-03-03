# Steganografija

Browser-based image steganography tool. Supports LSB (PNG), DCT coefficient (JPEG), and EXIF metadata (JPEG) embedding methods. Images are uploaded to a local server at `localhost:8000`.

## External Dependencies

| File | Purpose |
|------|---------|
| `steganography.js` | LSB steganography for PNG images (`steg` global) |
| `dct-steganography.js` | DCT coefficient steganography for JPEG via `@pinta365/steganography` CDN |
| `piexif.js` | EXIF read/write for JPEG via the `piexif` global |

Server API endpoints used: `POST /upload`, `GET /files`, `GET /images/{filename}`.

---

## UI Interactions

| Action | Result |
|--------|--------|
| Click **+** FAB | Opens the plain upload modal |
| **Ctrl+click** FAB | Opens the encode-and-upload modal |
| Click gallery card | Opens the image viewer (no decoding) |
| **Ctrl+click** gallery card | Opens the image viewer and decodes the hidden message |
| Press **Escape** | Closes the image viewer |

---

## JavaScript Functions

### `openUploadModal()`
Opens the encode-and-upload modal and locks page scrolling (`body.overflow = hidden`).

---

### `closeUploadModal()`
Closes the encode-and-upload modal and restores page scrolling.

---

### `handleUploadOverlayClick(e)`
Closes the encode-and-upload modal when the user clicks the backdrop (outside the modal box).

| Parameter | Type | Description |
|-----------|------|-------------|
| `e` | `MouseEvent` | Click event on the overlay element |

---

### `openPlainUploadModal()`
Opens the plain (un-encoded) image upload modal and locks page scrolling.

---

### `closePlainUploadModal()`
Closes the plain upload modal and restores page scrolling.

---

### `handlePlainUploadOverlayClick(e)`
Closes the plain upload modal when the user clicks the backdrop.

| Parameter | Type | Description |
|-----------|------|-------------|
| `e` | `MouseEvent` | Click event on the overlay element |

---

### `plainUploadImage()`
Uploads the file selected in `#plain-upload-file-input` directly to `API_BASE/upload` with no steganographic encoding. Shows status feedback and auto-closes the modal on success after 1.2 s.

---

### `handleFabClick(e)`
Handles the floating action button click. Ctrl+click opens the encode-and-upload modal; a plain click opens the plain upload modal.

| Parameter | Type | Description |
|-----------|------|-------------|
| `e` | `MouseEvent` | Click event from the FAB button |

---

### Module-level state

| Variable | Type | Description |
|----------|------|-------------|
| `uploadSourceImage` | `HTMLImageElement \| null` | The cover image element currently loaded in the encode modal |
| `uploadSourceFile` | `File \| null` | The original File object for the selected cover image |
| `_galleryFiles` | `string[]` | Cached list of filenames currently shown in the gallery grid |
| `API_BASE` | `string` | Base URL of the image server (`http://localhost:8000`) |

---

### `upload-file-input` change listener
Fires when the user picks a file in the encode modal. Clears previous state, loads the image via `loadFileAsImage`, shows or hides the JPEG method radio selector, and updates the format hint line with image dimensions.

---

### `embedExif(file, message)` → `Promise<string>`
Embeds a secret message into a JPEG file via the EXIF `ImageDescription` tag using `piexif.js`. Loads any existing EXIF data from the file, writes the message into `ImageIFD.ImageDescription`, then re-inserts the full EXIF block into the JPEG data URL.

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | `File` | Source JPEG file |
| `message` | `string` | Plaintext message to hide |

**Returns** a `Promise` that resolves with a `data:image/jpeg` DataURL containing the embedded message.

---

### `extractExif(blob)` → `Promise<string>`
Extracts a hidden message from a JPEG blob that was previously embedded via `embedExif`. Reads `ImageIFD.ImageDescription` from the EXIF segment using `piexif.js`. Resolves with an empty string if no EXIF data or no message is present — never rejects due to missing data.

| Parameter | Type | Description |
|-----------|------|-------------|
| `blob` | `Blob` | JPEG blob to inspect |

**Returns** a `Promise` that resolves with the hidden message string, or `''` if none found.

---

### `uploadImage()`
Encodes a secret message into the selected cover image and uploads the result to the server. Behaviour varies by file type and selected method:

- **PNG** — LSB encoding via `steg.encode` (`steganography.js`); result uploaded as `.png`.
- **JPEG + DCT** — coefficient embedding via `DCTSteganography.embed` (`dct-steganography.js`); result uploaded as `.jpg`.
- **JPEG + EXIF** — metadata embedding via `embedExif` (`piexif.js`); result uploaded as `.jpg`.

The radio group `input[name="jpeg-method"]` selects between DCT and EXIF for JPEG files. On success the modal auto-closes after 1.2 s.

---

### `showDecodedMessage(msgEl, message)`
Renders a decoded message string into a DOM element and applies the appropriate CSS state class.

| Parameter | Type | Description |
|-----------|------|-------------|
| `msgEl` | `HTMLElement` | The element that displays the message |
| `message` | `string` | Decoded message (may be empty) |

CSS classes applied: `viewer-message` (found), `viewer-message--none` (empty), `viewer-message--loading` (pending), `viewer-message--error` (decode failure).

---

### `openViewer(filename, showMessage)`
Opens the image viewer modal. Fetches the image from `API_BASE/images/{filename}` and displays it. When `showMessage` is `true`, also decodes and shows any hidden message:

- **JPEG** — tries EXIF extraction (`extractExif`) first; falls back to DCT extraction (`DCTSteganography.extract`) if the EXIF result is empty.
- **PNG** — uses LSB decoding via `steg.decode`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | `string` | Server filename to view, e.g. `photo.jpg` |
| `showMessage` | `boolean` | When `true`, the hidden-message panel is shown and decoded |

---

### `closeViewer()`
Closes the image viewer modal and restores page scrolling.

---

### `handleViewerOverlayClick(e)`
Closes the viewer modal when the user clicks the backdrop.

| Parameter | Type | Description |
|-----------|------|-------------|
| `e` | `MouseEvent` | Click event on the viewer overlay element |

---

### `loadGallery()`
Fetches the file list from `API_BASE/files` and synchronises the gallery grid with a smart diff: adds `<div class="gallery-card">` elements for new files and removes elements for deleted files. Avoids a full re-render to prevent image flicker. Called once on page load and then every 5 seconds via `setInterval`.

---

### `setStatus(id, msg, type)`
Updates a status message element with new text and a CSS type class.

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | `string` | Element ID of the status container |
| `msg` | `string` | Message text to display |
| `type` | `'info' \| 'success' \| 'error'` | Determines the CSS class applied (`status-info`, `status-success`, `status-error`) |

---

### `loadFileAsImage(file, callback)`
Reads a `File` object with `FileReader` and loads the result into a new `HTMLImageElement`. Invokes the callback with the loaded image on success, or `null` if loading fails.

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | `File` | Image file to read |
| `callback` | `(img: HTMLImageElement \| null) => void` | Called with the image element, or `null` on error |
