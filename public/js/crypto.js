/**
 * Secure Chat – End-to-End Encryption Module
 * ============================================
 * Uses the Web Crypto API for:
 *   - ECDH P-256 key pair generation
 *   - Shared secret derivation via ECDH (for DMs)
 *   - AES-GCM-256 encryption/decryption with HKDF key derivation
 *   - Group key management (raw AES-GCM key export/import)
 *   - File encryption/decryption (binary ArrayBuffer support)
 *
 * The server NEVER sees plaintext. All encryption/decryption
 * happens exclusively in the browser.
 */

class CryptoManager {
    constructor() {
        /** @type {CryptoKeyPair|null} */
        this.keyPair = null;

        /** @type {Map<string, CryptoKey>} peer username -> derived AES key */
        this.peerKeys = new Map();

        /** @type {Map<string, CryptoKey>} group id -> group AES key */
        this.groupKeys = new Map();
    }

    /* ─── Key Generation ──────────────────────────────────────────── */

    /** Generate a fresh ECDH P-256 key pair for this session. */
    async generateKeyPair() {
        this.keyPair = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,   // extractable (so we can export the public key)
            ["deriveKey", "deriveBits"]
        );
        return this.keyPair;
    }

    /** Export our public key as a JWK string. */
    async exportPublicKey() {
        if (!this.keyPair) await this.generateKeyPair();
        const jwk = await crypto.subtle.exportKey("jwk", this.keyPair.publicKey);
        return JSON.stringify(jwk);
    }

    /* ─── DM Key Exchange ────────────────────────────────────────── */

    /**
     * Import a peer's public key and derive a shared AES-GCM-256 key.
     * @param {string} peerUsername
     * @param {string} peerPublicKeyJwk  – JWK JSON string
     */
    async deriveSharedKey(peerUsername, peerPublicKeyJwk) {
        const jwk = JSON.parse(peerPublicKeyJwk);
        const peerPublicKey = await crypto.subtle.importKey(
            "jwk", jwk,
            { name: "ECDH", namedCurve: "P-256" },
            false, []
        );

        // Derive raw shared bits via ECDH
        const sharedBits = await crypto.subtle.deriveBits(
            { name: "ECDH", public: peerPublicKey },
            this.keyPair.privateKey,
            256
        );

        // Use HKDF to derive a proper AES-GCM key from the shared secret
        const hkdfKey = await crypto.subtle.importKey(
            "raw", sharedBits, "HKDF", false, ["deriveKey"]
        );

        const aesKey = await crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new TextEncoder().encode("secure-chat-salt-v1"),
                info: new TextEncoder().encode("secure-chat-aes-key"),
            },
            hkdfKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        this.peerKeys.set(peerUsername, aesKey);
        return aesKey;
    }

    /** Check if we have a derived key for a DM peer. */
    hasKeyFor(peerUsername) {
        return this.peerKeys.has(peerUsername);
    }

    /* ─── Group Key Management ───────────────────────────────────── */

    /**
     * Generate a new random AES-GCM-256 key for a group.
     * @returns {Promise<CryptoKey>}
     */
    async generateGroupKey() {
        return crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,  // extractable so we can export and share it
            ["encrypt", "decrypt"]
        );
    }

    /**
     * Export a group key as a base64 raw key string.
     * @param {CryptoKey} key
     * @returns {Promise<string>} base64
     */
    async exportGroupKeyRaw(key) {
        const raw = await crypto.subtle.exportKey("raw", key);
        return this._arrayBufferToBase64(raw);
    }

    /**
     * Import a raw base64 group key.
     * @param {string} base64Key
     * @returns {Promise<CryptoKey>}
     */
    async importGroupKeyRaw(base64Key) {
        const raw = this._base64ToArrayBuffer(base64Key);
        return crypto.subtle.importKey(
            "raw", raw,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    /**
     * Encrypt a raw group key with the shared DM key of a peer,
     * so we can send it securely over the wire.
     * @param {string} peerUsername
     * @param {string} groupKeyBase64 — raw exported group key
     * @returns {Promise<{encryptedKey: string, iv: string}>}
     */
    async encryptGroupKeyForPeer(peerUsername, groupKeyBase64) {
        const peerKey = this.peerKeys.get(peerUsername);
        if (!peerKey) throw new Error(`No shared key with ${peerUsername}`);
        const data = new TextEncoder().encode(groupKeyBase64);
        return this._encryptRaw(peerKey, data);
    }

    /**
     * Decrypt a group key received from the group creator.
     * @param {string} peerUsername — the sender (group creator)
     * @param {string} encryptedKeyB64
     * @param {string} ivB64
     * @returns {Promise<string>} base64 raw group key
     */
    async decryptGroupKeyFromPeer(peerUsername, encryptedKeyB64, ivB64) {
        const peerKey = this.peerKeys.get(peerUsername);
        if (!peerKey) throw new Error(`No shared key with ${peerUsername}`);
        const plainBuf = await this._decryptRaw(peerKey, encryptedKeyB64, ivB64);
        return new TextDecoder().decode(plainBuf);
    }

    /** Store a group's AES key by group ID. */
    setGroupKey(groupId, key) {
        this.groupKeys.set(groupId, key);
    }

    /** Get a group's AES key, if available. */
    getGroupKey(groupId) {
        return this.groupKeys.get(groupId) || null;
    }

    /** Check if we have a group key. */
    hasGroupKey(groupId) {
        return this.groupKeys.has(groupId);
    }

    /* ─── Encryption / Decryption ─────────────────────────────────── */

    /**
     * Encrypt a plaintext string for a DM peer.
     * Returns { payload: base64, iv: base64 }
     */
    async encrypt(peerUsername, plaintext) {
        const key = this.peerKeys.get(peerUsername);
        if (!key) throw new Error(`No encryption key for user: ${peerUsername}`);
        const encoded = new TextEncoder().encode(plaintext);
        return this._encryptRaw(key, encoded);
    }

    /**
     * Decrypt an incoming DM encrypted message.
     */
    async decrypt(peerUsername, payloadB64, ivB64) {
        const key = this.peerKeys.get(peerUsername);
        if (!key) throw new Error(`No decryption key for user: ${peerUsername}`);
        const plainBuf = await this._decryptRaw(key, payloadB64, ivB64);
        return new TextDecoder().decode(plainBuf);
    }

    /**
     * Encrypt a plaintext string for a group.
     */
    async encryptGroup(groupId, plaintext) {
        const key = this.groupKeys.get(groupId);
        if (!key) throw new Error(`No group key for group: ${groupId}`);
        const encoded = new TextEncoder().encode(plaintext);
        return this._encryptRaw(key, encoded);
    }

    /**
     * Decrypt a group message.
     */
    async decryptGroup(groupId, payloadB64, ivB64) {
        const key = this.groupKeys.get(groupId);
        if (!key) throw new Error(`No group key for group: ${groupId}`);
        const plainBuf = await this._decryptRaw(key, payloadB64, ivB64);
        return new TextDecoder().decode(plainBuf);
    }

    /**
     * Encrypt a binary file (ArrayBuffer) for a DM peer.
     */
    async encryptFile(peerUsernameOrGroupId, fileBuffer, isGroup = false) {
        const key = isGroup
            ? this.groupKeys.get(peerUsernameOrGroupId)
            : this.peerKeys.get(peerUsernameOrGroupId);
        if (!key) throw new Error(`No key for: ${peerUsernameOrGroupId}`);
        return this._encryptRaw(key, fileBuffer);
    }

    /**
     * Decrypt a binary file (ArrayBuffer) from a DM peer.
     */
    async decryptFile(peerUsernameOrGroupId, payloadB64, ivB64, isGroup = false) {
        const key = isGroup
            ? this.groupKeys.get(peerUsernameOrGroupId)
            : this.peerKeys.get(peerUsernameOrGroupId);
        if (!key) throw new Error(`No key for: ${peerUsernameOrGroupId}`);
        return this._decryptRaw(key, payloadB64, ivB64);
    }

    /* ─── Internal Primitives ─────────────────────────────────────── */

    async _encryptRaw(key, data) {
        const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            data
        );
        return {
            payload: this._arrayBufferToBase64(ciphertext),
            iv: this._arrayBufferToBase64(iv),
        };
    }

    async _decryptRaw(key, payloadB64, ivB64) {
        const ciphertext = this._base64ToArrayBuffer(payloadB64);
        const iv = this._base64ToArrayBuffer(ivB64);
        return crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            ciphertext
        );
    }

    /* ─── Utilities ──────────────────────────────────────────────── */

    _arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000;
        let binary = "";
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.subarray(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary);
    }

    _base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// Singleton
window.cryptoManager = new CryptoManager();
