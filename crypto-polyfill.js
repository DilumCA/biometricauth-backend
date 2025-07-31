import { webcrypto } from 'node:crypto';

// Polyfill for Web Crypto API in Node.js
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

// Additional polyfill for crypto.subtle if needed
if (!globalThis.crypto.subtle) {
  globalThis.crypto.subtle = webcrypto.subtle;
}