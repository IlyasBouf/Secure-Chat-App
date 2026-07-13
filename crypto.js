/**
 * crypto.js — End-to-End Encryption Module
 * ==========================================
 * Uses the Web Crypto API for:
 *  - ECDH key pair generation (P-256)
 *  - Public key export/import (JWK)
 *  - Shared secret derivation (ECDH → HKDF → AES-256-GCM key)
 *  - AES-GCM encrypt / decrypt with random IV
 */

const CryptoModule = (() => {
    // Store our key pair for this session
    let _keyPair = null;

    /**
     * Generate an ECDH key pair for this session.
     * @returns {Promise<CryptoKeyPair>}
     */
    async function generateKeyPair() {
        _keyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,   // extractable (so we can export the public key)
            ["deriveBits"]
        );
        console.log("[Crypto] ECDH key pair generated.");
        return _keyPair;
    }

    /**
     * Export our public key as JWK for sending to peers.
     * @returns {Promise<JsonWebKey>}
     */
    async function exportPublicKey() {
        if (!_keyPair) await generateKeyPair();
        const jwk = await window.crypto.subtle.exportKey("jwk", _keyPair.publicKey);
        return jwk;
    }

    /**
     * Import a peer's public key from JWK.
     * @param {JsonWebKey} jwk
     * @returns {Promise<CryptoKey>}
     */
    async function importPublicKey(jwk) {
        return window.crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );
    }

    /**
     * Derive a shared AES-GCM key from our private key + peer's public key.
     * Uses ECDH → raw bits → HKDF → AES-256-GCM key.
     * @param {CryptoKey} peerPublicKey
     * @returns {Promise<CryptoKey>}
     */
    async function deriveSharedKey(peerPublicKey) {
        if (!_keyPair) await generateKeyPair();

        // Step 1: ECDH → shared bits
        const sharedBits = await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: peerPublicKey },
            _keyPair.privateKey,
            256
        );

        // Step 2: Import shared bits as HKDF key material
        const hkdfKey = await window.crypto.subtle.importKey(
            "raw",
            sharedBits,
            "HKDF",
            false,
            ["deriveKey"]
        );

        // Step 3: HKDF → AES-256-GCM key
        const aesKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new Uint8Array(32),  // static salt (acceptable for ephemeral sessions)
                info: new TextEncoder().encode("secure-chat-e2e"),
            },
            hkdfKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        console.log("[Crypto] AES-256-GCM shared key derived via ECDH + HKDF.");
        return aesKey;
    }

    /**
     * Encrypt a plaintext string with AES-GCM.
     * @param {CryptoKey} key  — AES-GCM key
     * @param {string} plaintext
     * @returns {Promise<{iv: string, ciphertext: string}>}  — base64-encoded
     */
    async function encrypt(key, plaintext) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);

        const cipherBuf = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            encoded
        );

        return {
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(cipherBuf),
        };
    }

    /**
     * Decrypt an AES-GCM ciphertext.
     * @param {CryptoKey} key
     * @param {string} ivB64       — base64 IV
     * @param {string} ctB64       — base64 ciphertext
     * @returns {Promise<string>}  — plaintext
     */
    async function decrypt(key, ivB64, ctB64) {
        const iv = base64ToArrayBuffer(ivB64);
        const ct = base64ToArrayBuffer(ctB64);

        const plainBuf = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            ct
        );

        return new TextDecoder().decode(plainBuf);
    }

    // ---- helpers ----
    function arrayBufferToBase64(buf) {
        const bytes = new Uint8Array(buf);
        let binary = "";
        bytes.forEach((b) => (binary += String.fromCharCode(b)));
        return btoa(binary);
    }

    function base64ToArrayBuffer(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Public API
    return {
        generateKeyPair,
        exportPublicKey,
        importPublicKey,
        deriveSharedKey,
        encrypt,
        decrypt,
    };
})();
