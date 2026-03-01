class DCTSteganography {
  constructor() {
    this._lib = null;
  }

  async _loadLib() {
    if (!this._lib) {
      this._lib = await import('https://esm.sh/@pinta365/steganography@0.3.2');
    }
    return this._lib;
  }

  async embed(imageFile, message) {
    if (!imageFile || !message) {
      throw new Error('Invalid input: image and message required');
    }

    const lib = await this._loadLib();
    const arrayBuffer = await imageFile.arrayBuffer();
    const jpegData = new Uint8Array(arrayBuffer);

    const coefficients = await lib.extractJpegCoefficients(jpegData);
    if (!coefficients) {
      throw new Error('Failed to extract JPEG coefficients');
    }

    const capacity = lib.calculateJpegCoefficientCapacity(coefficients);
    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);
    const payloadSize = 4 + messageBytes.length;

    if (payloadSize > capacity) {
      throw new Error('Message exceeds capacity. Max: ' + (capacity - 4) + ' bytes');
    }

    const payload = new Uint8Array(payloadSize);
    new DataView(payload.buffer).setUint32(0, messageBytes.length, false);
    payload.set(messageBytes, 4);

    const cloned = lib.cloneJpegCoefficients(coefficients);
    lib.embedDataInJpegCoefficients(cloned, payload);

    const outputData = await lib.encodeJpegFromCoefficients(cloned);
    const blob = new Blob([outputData], { type: 'image/jpeg' });

    return new Promise(function(resolve) {
      var reader = new FileReader();
      reader.onload = function() { resolve(reader.result); };
      reader.readAsDataURL(blob);
    });
  }

  async extract(imageSource) {
    if (!imageSource) {
      throw new Error('Invalid input: image required');
    }

    const lib = await this._loadLib();
    let jpegData;

    if (imageSource instanceof Blob) {
      jpegData = new Uint8Array(await imageSource.arrayBuffer());
    } else if (imageSource instanceof Uint8Array) {
      jpegData = imageSource;
    } else if (imageSource instanceof ArrayBuffer) {
      jpegData = new Uint8Array(imageSource);
    } else {
      throw new Error('Invalid input: expected Blob, Uint8Array, or ArrayBuffer');
    }

    const coefficients = await lib.extractJpegCoefficients(jpegData);
    if (!coefficients) {
      throw new Error('Failed to extract JPEG coefficients');
    }

    const headerData = lib.extractDataFromJpegCoefficients(coefficients, 4);
    const view = new DataView(headerData.buffer, headerData.byteOffset, headerData.byteLength);
    const messageLength = view.getUint32(0, false);

    if (messageLength === 0 || messageLength > 10000000) {
      return '';
    }

    const fullData = lib.extractDataFromJpegCoefficients(coefficients, 4 + messageLength);
    const messageBytes = fullData.slice(4, 4 + messageLength);

    return new TextDecoder().decode(messageBytes);
  }

  async getCapacity(imageFile) {
    if (!imageFile) return 0;

    const lib = await this._loadLib();
    const arrayBuffer = await imageFile.arrayBuffer();
    const jpegData = new Uint8Array(arrayBuffer);

    const coefficients = await lib.extractJpegCoefficients(jpegData);
    if (!coefficients) return 0;

    return lib.calculateJpegCoefficientCapacity(coefficients) - 4;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DCTSteganography;
}

