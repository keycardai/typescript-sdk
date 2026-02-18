/*
 * Base64URL-ArrayBuffer
 * https://github.com/yackermann/Base64URL-ArrayBuffer
 *
 * Copyright (c) 2017 Yuriy Ackermann <ackermann.yuriy@gmail.com>
 * Copyright (c) 2012 Niklas von Hertzen
 * Licensed under the MIT license.
 *
 */

const CHARACTERS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Use a lookup table to find the index.
var lookup = new Uint8Array(256);
for (var i = 0; i < CHARACTERS.length; i++) {
  lookup[CHARACTERS.charCodeAt(i)] = i;
}

export default {
  encode: function (data: ArrayBuffer): string {
    var bytes = new Uint8Array(data),
      i,
      len = bytes.length,
      str = "";

    for (i = 0; i < len; i += 3) {
      str += CHARACTERS[bytes[i] >> 2];
      str += CHARACTERS[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
      str += CHARACTERS[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
      str += CHARACTERS[bytes[i + 2] & 63];
    }

    if (len % 3 === 2) {
      str = str.substring(0, str.length - 1);
    } else if (len % 3 === 1) {
      str = str.substring(0, str.length - 2);
    }

    return str;
  },

  decode: function (str: string): ArrayBuffer {
    var bufferLength = str.length * 0.75,
      len = str.length,
      i,
      p = 0,
      encoded1,
      encoded2,
      encoded3,
      encoded4;

    var data = new ArrayBuffer(bufferLength),
      bytes = new Uint8Array(data);

    for (i = 0; i < len; i += 4) {
      encoded1 = lookup[str.charCodeAt(i)];
      encoded2 = lookup[str.charCodeAt(i + 1)];
      encoded3 = lookup[str.charCodeAt(i + 2)];
      encoded4 = lookup[str.charCodeAt(i + 3)];

      bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
      bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
      bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }

    return data;
  },
};
