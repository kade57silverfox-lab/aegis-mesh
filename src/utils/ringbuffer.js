'use strict';

/**
 * Fixed-size ring buffer. Push is O(1), and toArray() returns samples in
 * chronological order (oldest first) without ever reallocating a growing array.
 */
class RingBuffer {
  constructor(size) {
    this.size = size;
    this.buffer = new Array(size);
    this.writeIndex = 0;
    this.count = 0;
  }

  push(value) {
    this.buffer[this.writeIndex] = value;
    this.writeIndex = (this.writeIndex + 1) % this.size;
    this.count = Math.min(this.count + 1, this.size);
  }

  toArray() {
    if (this.count < this.size) {
      return this.buffer.slice(0, this.count);
    }
    // oldest sample is at writeIndex (about to be overwritten next)
    return this.buffer.slice(this.writeIndex).concat(this.buffer.slice(0, this.writeIndex));
  }

  last(n) {
    const arr = this.toArray();
    return arr.slice(Math.max(0, arr.length - n));
  }

  latest() {
    if (this.count === 0) return undefined;
    const idx = (this.writeIndex - 1 + this.size) % this.size;
    return this.buffer[idx];
  }
}

module.exports = { RingBuffer };
