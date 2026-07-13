/**
 * Secure Chat – Main Application
 * ================================
 * Handles authentication, WebSocket connection, key exchange,
 * encrypted messaging, groups, and file sharing.
 */

(function () {
    "use strict";

    /* ── State ──────────────────────────────────────────────────── */
    const state = {
        token: null,
        username: null,
        ws: null,
        activeChat: null,    // { type: 'dm'|'group', id: string }
        onlineUsers: [],
        groups: [],          // Array of {id, name, members, creator}
        messages: {},        // id -> Array of messages
        pendingGroupKeys: [], // [{group, retries}] queue for group key distribution
        messageIds: new Set(), // For deduplication
    };

    const WS_PORT = 3001;
    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

    /* ── DOM refs ───────────────────────────────────────────────── */
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dom = {
        authView: $("#auth-view"),
        chatView: $("#chat-view"),
        loginForm: $("#login-form"),
        registerForm: $("#register-form"),
        authError: $("#auth-error"),
        contactsList: $("#contacts-list"),
        groupsList: $("#groups-list"),
        chatWelcome: $("#chat-welcome"),
        chatActive: $("#chat-active"),
        chatHeaderName: $("#chat-header-name"),
        chatHeaderAvatar: $("#chat-header-avatar"),
        chatHeaderSub: $("#chat-header-sub"),
        encryptionBadge: $("#encryption-badge"),
        messagesArea: $("#messages-area"),
        composerInput: $("#composer-input"),
        sendBtn: $("#send-btn"),
        attachBtn: $("#attach-btn"),
        fileInput: $("#file-input"),
        userBadgeName: $("#user-badge-name"),
        typingIndicator: $("#typing-indicator"),
        typingName: $("#typing-name"),
        connectionBar: $("#connection-bar"),
        newGroupBtn: $("#new-group-btn"),
        groupModal: $("#group-modal"),
        memberPicker: $("#member-picker"),
        createGroupBtn: $("#modal-create"),
        modalClose: $("#modal-close"),
        modalCancel: $("#modal-cancel"),
        addMemberBtn: $("#add-member-btn"),
        addMemberModal: $("#add-member-modal"),
        addMemberPicker: $("#add-member-picker"),
    };

    // Unread message counts: { chatId: number }
    const unreadCounts = {};

    /* ═══════════════════════════════════════════════════════════════
       AUTH
       ═══════════════════════════════════════════════════════════════ */

    $$(".auth-tab").forEach(tab => {
        tab.addEventListener("click", () => {
            $$(".auth-tab").forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            const target = tab.dataset.tab;
            $$(".auth-form").forEach(f => f.classList.remove("active"));
            $(`#${target}-form`).classList.add("active");
            dom.authError.textContent = "";
        });
    });

    dom.loginForm.addEventListener("submit", e => {
        e.preventDefault();
        authenticate("/api/login", $("#login-username").value.trim(), $("#login-password").value);
    });

    dom.registerForm.addEventListener("submit", e => {
        e.preventDefault();
        const u = $("#register-username").value.trim(), p = $("#register-password").value;
        if (p !== $("#register-confirm").value) return showAuthError("Passwords do not match");
        authenticate("/api/register", u, p);
    });

    async function authenticate(endpoint, username, password) {
        const btn = dom.authView.querySelector(".auth-submit");
        btn.disabled = true; btn.textContent = "Please wait...";
        try {
            const res = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });
            const data = await res.json();
            if (!res.ok) return showAuthError(data.error || "Auth failed");
            state.token = data.token; state.username = data.username;
            localStorage.setItem("chat_token", data.token);
            localStorage.setItem("chat_username", data.username);
            enterChat();
        } catch (err) { showAuthError("Server unreachable"); }
        finally { btn.disabled = false; btn.textContent = endpoint.includes("login") ? "Sign In" : "Create Account"; }
    }

    function showAuthError(msg) { dom.authError.textContent = msg; }

    /* ═══════════════════════════════════════════════════════════════
       CHAT INIT
       ═══════════════════════════════════════════════════════════════ */

    async function enterChat() {
        dom.authView.style.display = "none";
        dom.chatView.classList.add("active");
        dom.userBadgeName.textContent = state.username;
        await window.cryptoManager.generateKeyPair();
        connectWebSocket();
    }

    $("#logout-btn").addEventListener("click", () => {
        localStorage.clear();
        if (state.ws) state.ws.close();
        location.reload();
    });

    /* ═══════════════════════════════════════════════════════════════
       WEBSOCKET
       ═══════════════════════════════════════════════════════════════ */

    function connectWebSocket() {
        showConnectionStatus("connecting");
        state.ws = new WebSocket(`ws://${location.hostname}:${WS_PORT}`);
        state.ws.onopen = () => state.ws.send(JSON.stringify({ type: "auth", token: state.token }));
        state.ws.onmessage = e => handleWSMessage(JSON.parse(e.data));
        state.ws.onclose = () => {
            showConnectionStatus("disconnected");
            if (state.token) setTimeout(connectWebSocket, 3000);
        };
    }

    function showConnectionStatus(status) {
        dom.connectionBar.className = "connection-bar " + status;
        dom.connectionBar.textContent = status === "connecting" ? "⏳ Connecting..." : (status === "disconnected" ? "⚠ Disconnected" : "");
        dom.connectionBar.style.display = status === "connected" ? "none" : "block";
    }

    async function handleWSMessage(data) {
        switch (data.type) {
            case "auth-success":
                showConnectionStatus("connected");
                state.groups = data.groups || [];
                renderGroups();
                break;
            case "auth-error":
                // Token is invalid/expired — force re-login
                console.warn('Auth failed:', data.message);
                localStorage.clear();
                location.reload();
                break;
            case "user-list": {
                state.onlineUsers = data.users.filter(u => u !== state.username);
                renderContacts();
                // Update online count badge
                const countEl = document.getElementById('online-count');
                if (countEl) countEl.textContent = state.onlineUsers.length;
                break;
            }
            case "kicked":
                alert(data.message);
                localStorage.clear(); location.reload();
                break;
            case "key-exchange":
                await window.cryptoManager.deriveSharedKey(data.from, data.publicKey);
                state.ws.send(JSON.stringify({ type: "key-exchange-response", to: data.from, publicKey: await window.cryptoManager.exportPublicKey() }));
                console.log('[KeyExchange] Derived shared key with', data.from, '(responder)');
                updateEncryptionStatus();
                renderContacts();
                break;
            case "key-exchange-response":
                await window.cryptoManager.deriveSharedKey(data.from, data.publicKey);
                console.log('[KeyExchange] Derived shared key with', data.from, '(initiator)');
                updateEncryptionStatus();
                renderContacts();
                break;
            case "encrypted-message":
                handleIncomingDM(data);
                break;
            case "group-message":
                handleIncomingGroupMsg(data);
                break;
            case "group-created":
                if (!state.groups.find(g => g.id === data.group.id)) {
                    state.groups.push(data.group);
                }
                renderGroups();
                if (data.group.creator === state.username) {
                    startGroupKeyDistribution(data.group);
                }
                break;
            case "group-key-request":
                handleGroupKeyRequest(data);
                break;
            case "group-key-share":
                receiveGroupKey(data);
                break;
            case "group-member-added": {
                // Update group member list
                const existingGroup = state.groups.find(g => g.id === data.group.id);
                if (existingGroup) {
                    existingGroup.members = data.group.members;
                } else {
                    state.groups.push(data.group);
                }
                renderGroups();
                // If creator, distribute group key to new member
                if (data.group.creator === state.username && data.newMember) {
                    startGroupKeyDistribution(data.group);
                }
                break;
            }
            case "file-message":
                handleIncomingFile(data);
                break;
            case "typing":
                handleTypingIndicator(data);
                break;
            case "error":
                console.error("Server error:", data.message);
                break;
        }
    }

    /* ═══════════════════════════════════════════════════════════════
       MESSAGING
       ═══════════════════════════════════════════════════════════════ */

    async function sendMessage() {
        const text = dom.composerInput.value.trim();
        if (!text || !state.activeChat) return;
        const chat = state.activeChat, msgId = crypto.randomUUID();
        try {
            if (chat.type === 'dm') {
                if (!window.cryptoManager.hasKeyFor(chat.id)) {
                    addSystemMessage(chat.id, "⏳ Establishing secure channel before sending...");
                    await sendKeyExchange(chat.id);
                    await waitForKey(chat.id, 15000);
                }
                const { payload, iv } = await window.cryptoManager.encrypt(chat.id, text);
                state.ws.send(JSON.stringify({ type: "encrypted-message", to: chat.id, payload, iv, msgId, timestamp: Date.now() }));
            } else {
                if (!window.cryptoManager.hasGroupKey(chat.id)) {
                    addSystemMessage(chat.id, "⏳ Requesting group key...");
                    requestGroupKey(chat.id);
                    await waitForGroupKey(chat.id, 15000);
                }
                const { payload, iv } = await window.cryptoManager.encryptGroup(chat.id, text);
                state.ws.send(JSON.stringify({ type: "group-message", groupId: chat.id, payload, iv, msgId, timestamp: Date.now() }));
            }
            addMessage(chat.id, { from: state.username, text, time: Date.now(), msgId, sent: true });
            dom.composerInput.value = ""; dom.composerInput.style.height = "auto"; dom.sendBtn.disabled = true;
        } catch (e) { addSystemMessage(chat.id, "❌ Unable to send message"); }
    }

    async function handleIncomingDM(data) {
        if (state.messageIds.has(data.msgId)) return;
        state.messageIds.add(data.msgId);
        try {
            const text = await window.cryptoManager.decrypt(data.from, data.payload, data.iv);
            addMessage(data.from, { from: data.from, text, time: data.timestamp, msgId: data.msgId });
        } catch (e) { console.error("Decryption failed", e); }
    }

    async function handleIncomingGroupMsg(data) {
        if (state.messageIds.has(data.msgId)) return;
        state.messageIds.add(data.msgId);
        if (!window.cryptoManager.hasGroupKey(data.groupId)) return;
        try {
            const text = await window.cryptoManager.decryptGroup(data.groupId, data.payload, data.iv);
            addMessage(data.groupId, { from: data.from, text, time: data.timestamp, msgId: data.msgId });
        } catch (e) { console.error("Group decryption failed", e); }
    }

    /* ═══════════════════════════════════════════════════════════════
       FILES
       ═══════════════════════════════════════════════════════════════ */

    // File handling moved to modal section below for proper event binding

    async function handleIncomingFile(data) {
        if (state.messageIds.has(data.msgId)) return;
        state.messageIds.add(data.msgId);
        const chatId = data.groupId || data.from;
        try {
            const buffer = await window.cryptoManager.decryptFile(chatId, data.payload, data.iv, !!data.groupId);
            addMessage(chatId, { from: data.from, file: { name: data.fileName, type: data.fileType, size: data.fileSize, data: buffer }, time: data.timestamp, msgId: data.msgId });
        } catch (e) { console.error("File decryption failed", e); }
    }

    /* ═══════════════════════════════════════════════════════════════
       UI RENDERING
       ═══════════════════════════════════════════════════════════════ */

    function renderContacts() {
        dom.contactsList.innerHTML = state.onlineUsers.length ? state.onlineUsers.map(u => {
            const unread = unreadCounts[u] || 0;
            return `
            <div class="contact-item ${state.activeChat?.id === u ? 'active' : ''}" onclick="window.app.openChat('dm', '${u}')">
                <div class="contact-avatar">${u[0].toUpperCase()}<div class="online-dot"></div></div>
                <div class="contact-info">
                    <div class="contact-name">
                        <span class="contact-name-text">${u}</span>
                        ${unread > 0 ? '<span class="notif-icon" title="New message"></span>' : ''}
                    </div>
                    <div class="contact-status">${window.cryptoManager.hasKeyFor(u) ? '<span class="lock-icon">🔒</span> Encrypted' : 'Click to chat'}</div>
                </div>
                ${unread > 0 ? `<div class="unread-badge notif-badge">${unread}</div>` : ''}
            </div>`;
        }).join('') : '<div class="no-contacts"><p>No users online</p></div>';
    }

    function renderGroups() {
        dom.groupsList.innerHTML = state.groups.length ? state.groups.map(g => {
            const unread = unreadCounts[g.id] || 0;
            return `
            <div class="contact-item ${state.activeChat?.id === g.id ? 'active' : ''}" onclick="window.app.openChat('group', '${g.id}')">
                <div class="contact-avatar group-avatar">${g.name[0].toUpperCase()}</div>
                <div class="contact-info">
                    <div class="contact-name">
                        <span class="contact-name-text">${g.name}</span>
                        ${unread > 0 ? '<span class="notif-icon" title="New message"></span>' : ''}
                    </div>
                    <div class="contact-status">👥 ${(g.members || []).length} members</div>
                </div>
                ${unread > 0 ? `<div class="unread-badge notif-badge">${unread}</div>` : ''}
            </div>`;
        }).join('') : '<div class="no-contacts"><p>No groups</p></div>';
    }

    window.app = {
        openChat: async (type, id) => {
            state.activeChat = { type, id };
            // Clear unread count when opening a chat
            delete unreadCounts[id];
            renderContacts(); renderGroups();
            dom.chatWelcome.style.display = "none"; dom.chatActive.style.display = "flex";
            const group = state.groups.find(g => g.id === id);
            const name = type === 'dm' ? id : group.name;
            dom.chatHeaderName.textContent = name; dom.chatHeaderAvatar.textContent = name[0].toUpperCase();
            const memberCount = type === 'dm' ? 0 : (group?.members || []).length;
            dom.chatHeaderSub.textContent = type === 'dm' ? "Direct Message" : `👥 ${memberCount} members`;
            dom.messagesArea.innerHTML = "";
            (state.messages[id] || []).forEach(m => renderMessage(m));
            scrollToBottom();
            dom.composerInput.disabled = false; dom.composerInput.focus();
            if (type === 'dm' && !window.cryptoManager.hasKeyFor(id)) {
                sendKeyExchange(id);
                // The UI will show "Establishing..." until key-exchange-response updates it
            } else if (type === 'group' && !window.cryptoManager.hasGroupKey(id)) {
                requestGroupKey(id);
            }
            updateEncryptionStatus();
        }
    };

    function showToast(from, preview, chatId) {
        const toast = document.createElement('div');
        toast.className = 'toast-notif';
        toast.innerHTML = `<div class="toast-avatar">${from[0].toUpperCase()}</div><div class="toast-body"><strong>${from}</strong><p>${preview.substring(0, 60)}${preview.length > 60 ? '...' : ''}</p></div>`;
        toast.onclick = () => { window.app.openChat(state.groups.some(g => g.id === chatId) ? 'group' : 'dm', chatId); toast.remove(); };
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('visible'), 10);
        setTimeout(() => { toast.classList.remove('visible'); setTimeout(() => toast.remove(), 400); }, 4000);
    }

    function addMessage(chatId, msg) {
        if (!state.messages[chatId]) state.messages[chatId] = [];
        state.messages[chatId].push(msg);
        if (state.activeChat?.id === chatId) {
            renderMessage(msg);
            scrollToBottom();
        } else if (msg.from !== state.username) {
            // Increment unread badge for contacts not currently open
            unreadCounts[chatId] = (unreadCounts[chatId] || 0) + 1;
            renderContacts();
            renderGroups();
            showToast(msg.from, msg.text || `📎 ${msg.file?.name || 'File'}`, chatId);
        }
    }

    function renderMessage(msg) {
        const el = document.createElement("div");
        el.className = `message ${msg.sent ? 'sent' : 'received'}`;
        const time = new Date(msg.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        let content = "";
        if (msg.file) {
            const isImg = msg.file.type.startsWith("image/");
            const blob = new Blob([msg.file.data], { type: msg.file.type });
            const url = URL.createObjectURL(blob);
            if (isImg) content = `<img src="${url}" class="file-image-preview" onclick="window.open('${url}')">`;
            content += `<a href="${url}" download="${msg.file.name}" class="file-card">
                <div class="file-icon">${isImg ? '🖼' : '📄'}</div>
                <div class="file-info"><span class="file-name">${msg.file.name}</span><span class="file-size">${(msg.file.size/1024).toFixed(1)} KB</span></div>
            </a>`;
        } else {
            content = `<div class="message-bubble">${escapeHtml(msg.text)}</div>`;
        }

        el.innerHTML = `${content}<div class="message-meta"><span>🔒</span><span>${time}</span>${msg.from !== state.username ? ' • ' + msg.from : ''}</div>`;
        dom.messagesArea.appendChild(el);
    }

    function updateEncryptionStatus() {
        if (!state.activeChat) return;
        const id = state.activeChat.id, type = state.activeChat.type;
        const ok = type === 'dm' ? window.cryptoManager.hasKeyFor(id) : window.cryptoManager.hasGroupKey(id);
        dom.encryptionBadge.className = "encryption-badge " + (ok ? "" : "pending");
        dom.encryptionBadge.innerHTML = ok ? "🔒 End-to-End Encrypted" : "⏳ Establishing...";
    }

    function addSystemMessage(chatId, text) {
        if (state.activeChat?.id === chatId) {
            const el = document.createElement("div"); el.className = "system-message"; el.textContent = text;
            dom.messagesArea.appendChild(el); scrollToBottom();
        }
    }

    /**
     * Send key-exchange request (fire-and-forget).
     * The shared key will be available once we receive key-exchange-response.
     */
    async function sendKeyExchange(target) {
        if (window.cryptoManager.hasKeyFor(target)) return;
        console.log('[KeyExchange] Sending public key to', target);
        state.ws.send(JSON.stringify({
            type: "key-exchange",
            to: target,
            publicKey: await window.cryptoManager.exportPublicKey()
        }));
    }

    /**
     * Poll until we have a shared key with a peer.
     * Returns a promise that resolves when the key is available.
     */
    function waitForKey(peerUsername, maxWaitMs = 10000) {
        return new Promise((resolve, reject) => {
            if (window.cryptoManager.hasKeyFor(peerUsername)) return resolve();
            let elapsed = 0;
            const interval = setInterval(() => {
                elapsed += 200;
                if (window.cryptoManager.hasKeyFor(peerUsername)) {
                    clearInterval(interval);
                    resolve();
                } else if (elapsed >= maxWaitMs) {
                    clearInterval(interval);
                    reject(new Error(`Key exchange timeout for ${peerUsername}`));
                }
            }, 200);
        });
    }

    /**
     * Poll until we have a group key.
     */
    function waitForGroupKey(groupId, maxWaitMs = 10000) {
        return new Promise((resolve, reject) => {
            if (window.cryptoManager.hasGroupKey(groupId)) return resolve();
            let elapsed = 0;
            const interval = setInterval(() => {
                elapsed += 200;
                if (window.cryptoManager.hasGroupKey(groupId)) {
                    clearInterval(interval);
                    resolve();
                } else if (elapsed >= maxWaitMs) {
                    clearInterval(interval);
                    reject(new Error(`Group key timeout for ${groupId}`));
                }
            }, 200);
        });
    }

    /**
     * Request a group key from the creator (or distribute if we are creator).
     */
    function requestGroupKey(groupId) {
        const group = state.groups.find(g => g.id === groupId);
        if (!group || !state.ws || state.ws.readyState !== WebSocket.OPEN) return;
        if (group.creator && group.creator === state.username) {
            startGroupKeyDistribution(group);
            return;
        }
        state.ws.send(JSON.stringify({ type: "group-key-request", groupId }));
    }

    /**
     * Start group key distribution using setTimeout to avoid blocking handleWSMessage.
     */
    function startGroupKeyDistribution(group) {
        setTimeout(() => distributeGroupKey(group), 100);
    }

    /**
     * Creator distributes the group AES key to each member.
     * Uses polling (waitForKey) to wait for each ECDH handshake to complete.
     */
    async function distributeGroupKey(group, targetMembers = null) {
        try {
            let aesKey = window.cryptoManager.getGroupKey(group.id);
            let createdNew = false;
            if (!aesKey) {
                aesKey = await window.cryptoManager.generateGroupKey();
                window.cryptoManager.setGroupKey(group.id, aesKey);
                createdNew = true;
            }
            updateEncryptionStatus();
            const rawKey = await window.cryptoManager.exportGroupKeyRaw(aesKey);

            const groupMembers = group.members || [];
            const candidates = createdNew ? groupMembers : (targetMembers || groupMembers);
            const uniqueMembers = Array.from(new Set(candidates || [])).filter(m => groupMembers.includes(m));

            for (const member of uniqueMembers) {
                if (member === state.username) continue;
                try {
                    // Step 1: Initiate key exchange if needed (fire-and-forget)
                    if (!window.cryptoManager.hasKeyFor(member)) {
                        await sendKeyExchange(member);
                    }
                    // Step 2: Poll until shared key is available
                    await waitForKey(member, 12000);
                    console.log('[Group] Shared key ready for', member);

                    // Step 3: Encrypt group key with peer's shared key and send
                    const { payload: encryptedKey, iv } = await window.cryptoManager.encryptGroupKeyForPeer(member, rawKey);
                    state.ws.send(JSON.stringify({
                        type: "group-key-share",
                        to: member,
                        groupId: group.id,
                        encryptedKey,
                        iv
                    }));
                    console.log('[Group] Group key sent to', member);
                } catch (err) {
                    console.error(`Failed to share group key with ${member}:`, err);
                }
            }
            updateEncryptionStatus();
            renderGroups();
        } catch (err) {
            console.error('Group key distribution failed:', err);
        }
    }

    /**
     * Non-creator receives the encrypted group key from the creator.
     * Uses polling to wait for ECDH shared key if not yet available.
     */
    async function receiveGroupKey(data) {
        try {
            // If we don't have a key with the sender yet, send key exchange and wait
            if (!window.cryptoManager.hasKeyFor(data.from)) {
                await sendKeyExchange(data.from);
                await waitForKey(data.from, 12000);
            }
            const base64Key = await window.cryptoManager.decryptGroupKeyFromPeer(data.from, data.encryptedKey, data.iv);
            const importedKey = await window.cryptoManager.importGroupKeyRaw(base64Key);
            window.cryptoManager.setGroupKey(data.groupId, importedKey);
            console.log('[Group] Received and set group key for', data.groupId);
            updateEncryptionStatus();
            renderGroups();
        } catch (err) {
            console.error('Failed to receive group key:', err);
        }
    }

    async function handleGroupKeyRequest(data) {
        const group = state.groups.find(g => g.id === data.groupId);
        if (!group || group.creator !== state.username) return;
        await distributeGroupKey(group, [data.from]);
    }

    /* ── Helpers ────────────────────────────────────────────────── */
    function scrollToBottom() { dom.messagesArea.scrollTop = dom.messagesArea.scrollHeight; }
    function escapeHtml(t) { const d = document.createElement("div"); d.textContent = t; return d.innerHTML; }
    function handleTypingIndicator(d) {
        if ((d.groupId && state.activeChat?.id === d.groupId) || (!d.groupId && state.activeChat?.id === d.from)) {
            dom.typingName.textContent = d.from;
            dom.typingIndicator.classList.toggle("visible", d.isTyping);
        }
    }

    dom.composerInput.oninput = () => {
        dom.sendBtn.disabled = !dom.composerInput.value.trim();
        if (state.activeChat && state.ws) {
            state.ws.send(JSON.stringify({ type: "typing", to: state.activeChat.type === 'dm' ? state.activeChat.id : null, groupId: state.activeChat.type === 'group' ? state.activeChat.id : null, isTyping: true }));
            clearTimeout(window.tT); window.tT = setTimeout(() => state.ws.send(JSON.stringify({ type: "typing", to: state.activeChat.type === 'dm' ? state.activeChat.id : null, groupId: state.activeChat.type === 'group' ? state.activeChat.id : null, isTyping: false })), 2000);
        }
    };
    dom.composerInput.onkeydown = e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } };
    dom.sendBtn.onclick = sendMessage;

    /* ── Modals ─────────────────────────────────────────────────── */
    dom.newGroupBtn.onclick = () => {
        if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return alert('Not connected');
        dom.groupModal.style.display = "flex";
        if (state.onlineUsers.length === 0) {
            dom.memberPicker.innerHTML = '<p class="picker-empty">No other users online right now.</p>';
        } else {
            dom.memberPicker.innerHTML = state.onlineUsers.map(u =>
                `<div class="picker-item" data-user="${u}">
                    <div class="picker-checkbox">✓</div>
                    <div class="picker-avatar">${u[0].toUpperCase()}</div>
                    ${u}
                </div>`
            ).join('');
            dom.memberPicker.querySelectorAll('.picker-item').forEach(el => {
                el.addEventListener('click', () => el.classList.toggle('selected'));
            });
        }
    };

    const closeGroupModal = () => { dom.groupModal.style.display = "none"; $("#group-name-input").value = ""; };
    dom.modalClose.addEventListener('click', closeGroupModal);
    dom.modalCancel.addEventListener('click', closeGroupModal);
    dom.groupModal.addEventListener('click', e => { if (e.target === dom.groupModal) closeGroupModal(); });

    dom.createGroupBtn.onclick = () => {
        const name = $("#group-name-input").value.trim();
        if (!name) { alert('Please enter a group name'); return; }
        const members = Array.from(dom.memberPicker.querySelectorAll(".picker-item.selected")).map(el => el.dataset.user);
        state.ws.send(JSON.stringify({ type: "create-group", name, members }));
        closeGroupModal();
    };

    // File attach — use addEventListener for reliability
    dom.attachBtn.addEventListener('click', () => {
        if (!state.activeChat) return alert('Select a chat first');
        dom.fileInput.value = ''; // Reset so same file can be re-selected
        dom.fileInput.click();
    });
    dom.fileInput.addEventListener('change', async () => {
        const file = dom.fileInput.files[0];
        if (!file || !state.activeChat) return;
        if (file.size > MAX_FILE_SIZE) return alert('File too large (max 5 MB)');
        const chat = state.activeChat;
        const isGroup = chat.type === 'group';
        try {
            if (isGroup && !window.cryptoManager.hasGroupKey(chat.id)) {
                addSystemMessage(chat.id, "⏳ Requesting group key before sending file...");
                requestGroupKey(chat.id);
                await waitForGroupKey(chat.id, 15000);
            }
            if (!isGroup && !window.cryptoManager.hasKeyFor(chat.id)) {
                addSystemMessage(chat.id, "⏳ Establishing secure channel before sending file...");
                await sendKeyExchange(chat.id);
                await waitForKey(chat.id, 15000);
            }
            const msgId = crypto.randomUUID();
            const buffer = await file.arrayBuffer();
            const { payload, iv } = await window.cryptoManager.encryptFile(chat.id, buffer, isGroup);
            const msgObj = { type: 'file-message', msgId, timestamp: Date.now(), payload, iv, fileName: file.name, fileType: file.type, fileSize: file.size };
            if (isGroup) msgObj.groupId = chat.id; else msgObj.to = chat.id;
            state.ws.send(JSON.stringify(msgObj));
            addMessage(chat.id, { from: state.username, file: { name: file.name, type: file.type, size: file.size, data: buffer }, time: Date.now(), msgId, sent: true });
        } catch (err) {
            console.error('File send error:', err);
            alert('Failed to send file: ' + err.message);
        } finally {
            dom.fileInput.value = '';
        }
    });

    /* ── Add Member Modal ──────────────────────────────────────── */
    const closeAddMemberModal = () => { dom.addMemberModal.style.display = "none"; };
    $('#add-member-modal-close').addEventListener('click', closeAddMemberModal);
    $('#add-member-cancel').addEventListener('click', closeAddMemberModal);
    dom.addMemberModal.addEventListener('click', e => { if (e.target === dom.addMemberModal) closeAddMemberModal(); });

    dom.addMemberBtn.addEventListener('click', () => {
        if (!state.activeChat || state.activeChat.type !== 'group') return;
        const group = state.groups.find(g => g.id === state.activeChat.id);
        if (!group) return;
        // Show only online users not already in the group
        const eligible = state.onlineUsers.filter(u => !group.members.includes(u));
        if (eligible.length === 0) {
            dom.addMemberPicker.innerHTML = '<p class="picker-empty">No eligible users online.</p>';
        } else {
            dom.addMemberPicker.innerHTML = eligible.map(u =>
                `<div class="picker-item" data-user="${u}">
                    <div class="picker-checkbox">✓</div>
                    <div class="picker-avatar">${u[0].toUpperCase()}</div>
                    ${u}
                </div>`
            ).join('');
            dom.addMemberPicker.querySelectorAll('.picker-item').forEach(el => {
                el.addEventListener('click', () => el.classList.toggle('selected'));
            });
        }
        dom.addMemberModal.style.display = "flex";
    });

    $('#add-member-confirm').addEventListener('click', () => {
        const selected = Array.from(dom.addMemberPicker.querySelectorAll('.picker-item.selected')).map(el => el.dataset.user);
        if (selected.length === 0) return;
        const groupId = state.activeChat?.id;
        if (!groupId) return;
        selected.forEach(username => {
            state.ws.send(JSON.stringify({ type: 'group-add-member', groupId, username }));
        });
        closeAddMemberModal();
    });

    (function init() {
        const t = localStorage.getItem("chat_token"), u = localStorage.getItem("chat_username");
        if (t && u) { state.token = t; state.username = u; enterChat(); }
    })();
})();
