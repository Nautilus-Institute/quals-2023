import { decode as base64Decode, encode as base64Encode } from 'https://deno.land/std@0.166.0/encoding/base64.ts'

// Polyfill a small subset of node buffer functionality
export function Buffer(ab) {
  console.log('ab',ab);
  this.buffer = new DataView(ab);
  this.length = this.buffer.byteLength;
}
Buffer.prototype.readUInt8 = function(offset) {
  return this.buffer.getUint8(offset);
}
Buffer.prototype.readUInt16LE = function(offset) {
  return this.buffer.getUint16(offset, true);
}
Buffer.prototype.readUInt16BE = function(offset) {
  return this.buffer.getUint16(offset, false);
}
Buffer.prototype.readUInt32LE = function(offset) {
  return this.buffer.getUint32(offset, true);
}
Buffer.prototype.readInt32LE = function(offset) {
  return this.buffer.getInt32(offset, true);
}
Buffer.prototype.readUInt32BE = function(offset) {
  return this.buffer.getUint32(offset, false);
}
Buffer.prototype.writeUInt32LE = function(n, offset) {
  this.buffer.setUint32(offset, n, true);
}
Buffer.prototype.slice = function(start, end) {
  return new Buffer(this.buffer.buffer.slice(start, end));
}
Buffer.prototype.toString = function(enc) {
  console.log("toString", this.buffer);
  if (!enc) enc = 'utf8';
  if (enc == 'utf8') {
    return new TextDecoder().decode(this.buffer.buffer);
  }
  if (enc == 'base64') {
    return base64Encode(this.buffer.buffer);
  }
  throw new Error('Unsupported encoding');
}
Buffer.prototype.arrayBuffer = function() {
  return this.buffer.buffer;
}
Buffer.alloc = function(n) {
  return new Buffer(new ArrayBuffer(n));
}
Buffer.from = function(s, enc) {
  if (s instanceof Buffer) {
    return new Buffer(s.buffer.buffer.slice(0));
  }
  if (s instanceof Array) {
    return new Buffer(new Uint8Array(s).buffer);
  }

  s = s.toString();
  if (enc == 'base64') {
    try {
      var a = base64Decode(s);
      var b = new Buffer(a.buffer);
      return b
    } catch (e) {
      console.error(e);
      enc = 'ascii';
    }
  }
  var b = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) {
    b[i] = s.charCodeAt(i);
  }
  return new Buffer(b.buffer);
}
Buffer.concat = function(buffers) {
  var out = new Uint8Array(buffers.reduce((acc, b) => acc + b.length, 0));
  var offset = 0;
  for (var i = 0; i < buffers.length; i++) {
    out.set(new Uint8Array(buffers[i].buffer.buffer), offset);
    offset += buffers[i].length;
  }
  return new Buffer(out.buffer);
}
