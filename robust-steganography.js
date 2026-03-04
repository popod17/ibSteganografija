/**
 * RobustSteganography — pixel-domain spread-spectrum embedding.
 *
 * Each message bit is spread across SPREAD_FACTOR non-overlapping 8×8 blocks
 * using a seeded pseudo-random ±1 pattern. On extraction, correlation with the
 * same pattern recovers the original bit even after JPEG re-compression.
 *
 * Everything runs client-side via Canvas — no network calls, no external
 * dependencies.  Works with both PNG and JPEG cover images.
 *
 * Defaults: SPREAD_FACTOR = 64, STRENGTH = 15  (most-robust preset).
 *
 * Usage:
 *   var rs = new RobustSteganography();
 *   var dataURL = await rs.embed(imageElement, 'secret', 'image/jpeg', 0.85);
 *   var message = await rs.extract(imageElement);
 *   var bytes   = rs.getCapacity(width, height);
 */
;(function (name, context, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else if (typeof define === 'function' && define.amd) {
        define(factory);
    } else {
        context[name] = factory();
    }
})('RobustSteganography', this, function () {

    /* ── Constructor ──────────────────────────────────────────────────── */

    /**
     * @param {object} [options]
     * @param {number} [options.spreadFactor=64]  Blocks per message bit
     * @param {number} [options.strength=15]      Pixel delta amplitude
     * @param {number} [options.seed=0x57E60]     PRNG seed (must match on
     *                                            embed & extract)
     */
    function RobustSteganography(options) {
        var opts = options || {};
        this.BLOCK_SIZE    = 8;
        this.SPREAD_FACTOR = opts.spreadFactor || 64;
        this.STRENGTH      = opts.strength     || 15;
        this.SEED          = opts.seed         || 0x57E60;
    }

    /* ── PRNG (xorshift32, seeded) ────────────────────────────────────── */

    RobustSteganography.prototype._prng = function (seed) {
        var state = (seed | 0) || 1;
        return function () {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            return (state >>> 0);
        };
    };

    /** Generate a ±1 pattern for one 8×8 block (64 values). */
    RobustSteganography.prototype._blockPattern = function (seed) {
        var rng = this._prng(seed);
        var pattern = new Int8Array(64);
        for (var i = 0; i < 64; i++) {
            pattern[i] = (rng() & 1) ? 1 : -1;
        }
        return pattern;
    };

    /* ── Block grid ───────────────────────────────────────────────────── */

    /** All non-overlapping 8×8 block positions → [{x,y}, …] */
    RobustSteganography.prototype._getBlocks = function (width, height) {
        var blocks = [];
        for (var y = 0; y + this.BLOCK_SIZE <= height; y += this.BLOCK_SIZE) {
            for (var x = 0; x + this.BLOCK_SIZE <= width; x += this.BLOCK_SIZE) {
                blocks.push({ x: x, y: y });
            }
        }
        return blocks;
    };

    /* ── Capacity ─────────────────────────────────────────────────────── */

    /**
     * Max message bytes for the given image dimensions.
     *
     *   totalBlocks  = floor(W/8) × floor(H/8)
     *   totalBits    = floor(totalBlocks / SPREAD_FACTOR)
     *   capacity     = floor((totalBits − 32) / 8)   [32 bits = length header]
     */
    RobustSteganography.prototype.getCapacity = function (width, height) {
        var totalBlocks = this._getBlocks(width, height).length;
        var totalBits   = Math.floor(totalBlocks / this.SPREAD_FACTOR);
        return Math.max(0, Math.floor((totalBits - 32) / 8));
    };

    /* ── Image-loading helper ─────────────────────────────────────────── */

    /**
     * Accept HTMLImageElement | Blob | File | data-URL string →
     * { canvas, ctx, imageData }
     */
    RobustSteganography.prototype._loadImageData = function (source) {
        return new Promise(function (resolve, reject) {

            function fromImage(img) {
                var w = img.naturalWidth  || img.width;
                var h = img.naturalHeight || img.height;
                var canvas = document.createElement('canvas');
                canvas.width  = w;
                canvas.height = h;
                var ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                resolve({
                    canvas:    canvas,
                    ctx:       ctx,
                    imageData: ctx.getImageData(0, 0, w, h)
                });
            }

            if (source instanceof HTMLImageElement) {
                if (source.complete && source.naturalWidth > 0) { fromImage(source); }
                else {
                    source.onload  = function () { fromImage(source); };
                    source.onerror = function () { reject(new Error('Image failed to load')); };
                }
            } else if (source instanceof Blob || source instanceof File) {
                var url = URL.createObjectURL(source);
                var img = new Image();
                img.onload  = function () { URL.revokeObjectURL(url); fromImage(img); };
                img.onerror = function () { URL.revokeObjectURL(url); reject(new Error('Image failed to load')); };
                img.src = url;
            } else if (typeof source === 'string') {
                var img2 = new Image();
                img2.onload  = function () { fromImage(img2); };
                img2.onerror = function () { reject(new Error('Image failed to load')); };
                img2.src = source;
            } else {
                reject(new Error('Unsupported source type'));
            }
        });
    };

    /* ── Embed ────────────────────────────────────────────────────────── */

    /**
     * Embed a UTF-8 message into an image using spread-spectrum modulation.
     *
     * @param  {HTMLImageElement|Blob|File|string} source   Cover image
     * @param  {string}  message                            Secret text
     * @param  {string}  [mimeType='image/png']             Output format
     * @param  {number}  [quality=0.92]                     JPEG quality (0–1)
     * @return {Promise<string>}  Data URL of the stego image
     */
    RobustSteganography.prototype.embed = function (source, message, mimeType, quality) {
        mimeType = mimeType || 'image/png';
        quality  = (quality !== undefined) ? quality : 0.92;
        var self = this;

        return this._loadImageData(source).then(function (loaded) {
            var canvas    = loaded.canvas;
            var ctx       = loaded.ctx;
            var imageData = loaded.imageData;
            var width     = canvas.width;
            var height    = canvas.height;
            var data      = imageData.data;

            // Payload: 4-byte BE length + UTF-8 message
            var msgBytes = new TextEncoder().encode(message);
            var payload  = new Uint8Array(4 + msgBytes.length);
            new DataView(payload.buffer).setUint32(0, msgBytes.length, false);
            payload.set(msgBytes, 4);

            // Convert to bits
            var bits = [];
            for (var bi = 0; bi < payload.length; bi++) {
                for (var b = 7; b >= 0; b--) {
                    bits.push((payload[bi] >> b) & 1);
                }
            }

            var blocks = self._getBlocks(width, height);
            var needed = bits.length * self.SPREAD_FACTOR;
            if (needed > blocks.length) {
                throw new Error(
                    'Message too long. Need ' + needed + ' blocks, have ' +
                    blocks.length + '. Max capacity: ' +
                    self.getCapacity(width, height) + ' bytes.'
                );
            }

            // Embed each bit across SPREAD_FACTOR blocks
            for (var i = 0; i < bits.length; i++) {
                var bitVal = bits[i] ? 1 : -1;

                for (var s = 0; s < self.SPREAD_FACTOR; s++) {
                    var blockIdx = i * self.SPREAD_FACTOR + s;
                    var block    = blocks[blockIdx];
                    var pattern  = self._blockPattern(
                        self.SEED + i * self.SPREAD_FACTOR + s
                    );

                    for (var dy = 0; dy < self.BLOCK_SIZE; dy++) {
                        for (var dx = 0; dx < self.BLOCK_SIZE; dx++) {
                            var px     = ((block.y + dy) * width + (block.x + dx)) * 4;
                            var patIdx = dy * self.BLOCK_SIZE + dx;
                            var delta  = bitVal * pattern[patIdx] * self.STRENGTH;

                            data[px]     = Math.max(0, Math.min(255, data[px]     + delta));
                            data[px + 1] = Math.max(0, Math.min(255, data[px + 1] + delta));
                            data[px + 2] = Math.max(0, Math.min(255, data[px + 2] + delta));
                        }
                    }
                }
            }

            ctx.putImageData(imageData, 0, 0);
            return canvas.toDataURL(mimeType, quality);
        });
    };

    /* ── Extract ──────────────────────────────────────────────────────── */

    /**
     * Extract a hidden message from a stego image.
     *
     * @param  {HTMLImageElement|Blob|File|string} source
     * @return {Promise<string>}  Extracted text, or '' if none found
     */
    RobustSteganography.prototype.extract = function (source) {
        var self = this;

        return this._loadImageData(source).then(function (loaded) {
            var imageData = loaded.imageData;
            var width     = loaded.canvas.width;
            var height    = loaded.canvas.height;
            var data      = imageData.data;
            var blocks    = self._getBlocks(width, height);

            // 32-bit length header
            var headerBits = self._correlate(data, width, blocks, 0, 32);

            var lengthBuf = new ArrayBuffer(4);
            var view      = new DataView(lengthBuf);
            for (var i = 0; i < 4; i++) {
                var byte = 0;
                for (var b = 0; b < 8; b++) {
                    byte = (byte << 1) | headerBits[i * 8 + b];
                }
                view.setUint8(i, byte);
            }
            var msgLength = view.getUint32(0, false);

            var maxBytes = self.getCapacity(width, height);
            if (msgLength <= 0 || msgLength > maxBytes || msgLength > 100000) {
                return '';
            }

            var totalBits = 32 + msgLength * 8;
            if (totalBits * self.SPREAD_FACTOR > blocks.length) {
                return '';
            }

            var allBits = self._correlate(data, width, blocks, 0, totalBits);

            var msgBytes = new Uint8Array(msgLength);
            for (var m = 0; m < msgLength; m++) {
                var mbyte = 0;
                for (var mb = 0; mb < 8; mb++) {
                    mbyte = (mbyte << 1) | allBits[32 + m * 8 + mb];
                }
                msgBytes[m] = mbyte;
            }

            try {
                return new TextDecoder().decode(msgBytes);
            } catch (e) {
                return '';
            }
        });
    };

    /* ── Correlation detector ─────────────────────────────────────────── */

    /**
     * Recover bits by correlating pixel values with the spread patterns.
     *
     * For each bit the detector sums  pixel × pattern  across R, G, B and
     * all SPREAD_FACTOR blocks.  Compression noise is zero-mean and
     * uncorrelated with the pattern, so it averages out.
     */
    RobustSteganography.prototype._correlate = function (data, width, blocks, startBit, count) {
        var bits = [];

        for (var i = startBit; i < startBit + count; i++) {
            var correlation = 0;

            for (var s = 0; s < this.SPREAD_FACTOR; s++) {
                var blockIdx = i * this.SPREAD_FACTOR + s;
                var block    = blocks[blockIdx];
                var pattern  = this._blockPattern(
                    this.SEED + i * this.SPREAD_FACTOR + s
                );

                for (var dy = 0; dy < this.BLOCK_SIZE; dy++) {
                    for (var dx = 0; dx < this.BLOCK_SIZE; dx++) {
                        var px     = ((block.y + dy) * width + (block.x + dx)) * 4;
                        var patIdx = dy * this.BLOCK_SIZE + dx;

                        correlation += data[px]     * pattern[patIdx];
                        correlation += data[px + 1] * pattern[patIdx];
                        correlation += data[px + 2] * pattern[patIdx];
                    }
                }
            }

            bits.push(correlation > 0 ? 1 : 0);
        }
        return bits;
    };

    return RobustSteganography;
});
