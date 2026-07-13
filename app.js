/**
 * app.js — Secure Chat Application Logic
 * ========================================
 * Orchestrates WebSocket communication, authentication,
 * key exchange, encryption, and UI rendering.
 */

(() => {
    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------
    let ws = null;
    let currentUser = null;
    let selectedUser = null;

    // Per-peer encryption keys:  { username: CryptoKey }
    const sharedKeys = {};
    // Pending key exchanges:     { username: resolve_function }
    const pendingKeyExchanges = {};
    // Per-peer message history:  { username: [{from, text, time}] }
    const messageHistory = {};
    // Typing indicator timers
    const typingTimers = {};

    // -----------------------------------------------------------------------
    // DOM references
    // -----------------------------------------------------------------------
    const $ = (sel) => document.querySelector(sel);
    const authScreen = $("#auth-screen");
    const chatScreen = $("#chat-screen");
    const loginForm = $("#login-form");
    const registerForm = $("#register-form");
    const authError = $("#auth-error");
    const authSuccess = $("#auth-success");
    const showRegisterBtn = $("#show-register");
    const showLoginBtn = $("#show-login");
    const authTitle = $("#auth-title");

    const userListEl = $("#user-list");
    const messagesEl = $("#messages");
    const msgInput = $("#msg-input");
    const sendBtn = $("#send-btn");
    const chatWithEl = $("#chat-with");
    const currentUserEl = $("#current-user");
    const logoutBtn = $("#logout-btn");
    const typingIndicator = $("#typing-indicator");
    const noChatSelected = $("#no-chat-selected");
    const chatArea = $("#chat-area");
    const onlineCount = $("#online-count");
    const encryptionBadge = $("#encryption-badge");

    // -----------------------------------------------------------------------
    // WebSocket connection
    // -----------------------------------------------------------------------
    function connect() {
        const wsUrl = `ws://${location.hostname}:8765`;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => console.log("[WS] Connected");
        ws.onclose = () => {
            console.log("[WS] Disconnected — reconnecting in 2s...");
            setTimeout(connect, 2000);
        };
        ws.onerror = (e) => console.error("[WS] Error", e);
        ws.onmessage = (e) => handleMessage(JSON.parse(e.data));
    }

    // -----------------------------------------------------------------------
    // Incoming message router
    // -----------------------------------------------------------------------
    function handleMessage(data) {
        switch (data.type) {
            case "register_result":
                handleAuthResult(data, true);
                break;
            case "login_result":
                handleLoginResult(data);
                break;
            case "user_list":
                renderUserList(data.users);
                break;
            case "key_exchange":
                handleKeyExchange(data);
                break;
            case "key_exchange_response":
                handleKeyExchangeResponse(data);
                break;
            case "encrypted_message":
                handleEncryptedMessage(data);
                break;
            case "typing":
                handleTypingIndicator(data);
                break;
            case "error":
                console.warn("[Server]", data.message);
                break;
        }
    }

    // -----------------------------------------------------------------------
    // Auth
    // -----------------------------------------------------------------------
    function handleAuthResult(data, isRegister) {
        if (data.success) {
            authError.textContent = "";
            authSuccess.textContent = data.message + (isRegister ? " You can now log in." : "");
            authSuccess.classList.add("visible");
            if (isRegister) {
                // Switch to login view
                setTimeout(() => {
                    showLoginView();
                    authSuccess.classList.remove("visible");
                }, 1500);
            }
        } else {
            authSuccess.textContent = "";
            authSuccess.classList.remove("visible");
            authError.textContent = data.message;
        }
    }

    function handleLoginResult(data) {
        if (data.success) {
            currentUser = loginForm.querySelector('[name="username"]').value.trim();
            authScreen.classList.remove("active");
            chatScreen.classList.add("active");
            currentUserEl.textContent = currentUser;
            authError.textContent = "";
            authSuccess.textContent = "";
            authSuccess.classList.remove("visible");
            // Generate key pair for this session
            CryptoModule.generateKeyPair();
        } else {
            handleAuthResult(data, false);
        }
    }

    // Login form submit
    loginForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const username = loginForm.querySelector('[name="username"]').value.trim();
        const password = loginForm.querySelector('[name="password"]').value;
        ws.send(JSON.stringify({ type: "login", username, password }));
    });

    // Register form submit
    registerForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const username = registerForm.querySelector('[name="username"]').value.trim();
        const password = registerForm.querySelector('[name="password"]').value;
        const confirm = registerForm.querySelector('[name="confirm"]').value;
        if (password !== confirm) {
            authError.textContent = "Passwords do not match.";
            return;
        }
        ws.send(JSON.stringify({ type: "register", username, password }));
    });

    // Toggle login/register views
    showRegisterBtn.addEventListener("click", (e) => {
        e.preventDefault();
        showRegisterView();
    });

    showLoginBtn.addEventListener("click", (e) => {
        e.preventDefault();
        showLoginView();
    });

    function showRegisterView() {
        loginForm.classList.remove("active");
        registerForm.classList.add("active");
        authTitle.textContent = "Create Account";
        authError.textContent = "";
        authSuccess.textContent = "";
        authSuccess.classList.remove("visible");
    }

    function showLoginView() {
        registerForm.classList.remove("active");
        loginForm.classList.add("active");
        authTitle.textContent = "Welcome Back";
        authError.textContent = "";
    }

    // Logout
    logoutBtn.addEventListener("click", () => {
        ws.close();
        currentUser = null;
        selectedUser = null;
        Object.keys(sharedKeys).forEach((k) => delete sharedKeys[k]);
        Object.keys(messageHistory).forEach((k) => delete messageHistory[k]);
        chatScreen.classList.remove("active");
        authScreen.classList.add("active");
        loginForm.reset();
        registerForm.reset();
        setTimeout(connect, 500);
    });

    // -----------------------------------------------------------------------
    // User list
    // -----------------------------------------------------------------------
    function renderUserList(users) {
        const others = users.filter((u) => u !== currentUser);
        onlineCount.textContent = others.length;

        userListEl.innerHTML = "";
        if (others.length === 0) {
            userListEl.innerHTML = `
                <div class="no-users">
                    <span class="no-users-icon">👥</span>
                    <p>No other users online</p>
                </div>`;
            return;
        }
        others.forEach((user) => {
            const li = document.createElement("li");
            li.className = "user-item" + (user === selectedUser ? " active" : "");
            li.innerHTML = `
                <div class="user-avatar">${user[0].toUpperCase()}</div>
                <div class="user-info">
                    <span class="user-name">${escapeHtml(user)}</span>
                    <span class="user-status">${sharedKeys[user] ? "🔐 Encrypted" : "Online"}</span>
                </div>
                ${messageHistory[user]?.length ? `<span class="unread-dot${user === selectedUser ? " seen" : ""}"></span>` : ""}
            `;
            li.addEventListener("click", () => selectUser(user));
            userListEl.appendChild(li);
        });
    }

    // -----------------------------------------------------------------------
    // Chat selection
    // -----------------------------------------------------------------------
    function selectUser(user) {
        selectedUser = user;
        chatWithEl.textContent = user;
        noChatSelected.style.display = "none";
        chatArea.style.display = "flex";
        encryptionBadge.style.display = sharedKeys[user] ? "flex" : "none";

        // Re-render user list to highlight
        const items = userListEl.querySelectorAll(".user-item");
        items.forEach((li) => li.classList.remove("active"));
        // Find the clicked one (could also re-render)
        items.forEach((li) => {
            if (li.querySelector(".user-name")?.textContent === user) {
                li.classList.add("active");
            }
        });

        renderMessages();
        msgInput.focus();
    }

    // -----------------------------------------------------------------------
    // Key Exchange
    // -----------------------------------------------------------------------
    /**
     * Initiate ECDH key exchange with a peer.
     * Returns a promise that resolves when the shared key is established.
     */
    async function initiateKeyExchange(target) {
        if (sharedKeys[target]) return; // already have a key

        const pubKey = await CryptoModule.exportPublicKey();
        ws.send(JSON.stringify({
            type: "key_exchange",
            target,
            publicKey: pubKey,
        }));
        console.log(`[KeyExchange] Sent public key to ${target}`);

        // Wait for response
        return new Promise((resolve) => {
            pendingKeyExchanges[target] = resolve;
        });
    }

    /**
     * Handle incoming key exchange request (from initiator).
     */
    async function handleKeyExchange(data) {
        const peerName = data.from;
        console.log(`[KeyExchange] Received public key from ${peerName}`);

        // Import their public key and derive shared secret
        const peerPub = await CryptoModule.importPublicKey(data.publicKey);
        const aesKey = await CryptoModule.deriveSharedKey(peerPub);
        sharedKeys[peerName] = aesKey;

        // Send our public key back
        const ourPub = await CryptoModule.exportPublicKey();
        ws.send(JSON.stringify({
            type: "key_exchange_response",
            target: peerName,
            publicKey: ourPub,
        }));
        console.log(`[KeyExchange] Responded with our public key to ${peerName}`);

        // Update UI
        if (selectedUser === peerName) {
            encryptionBadge.style.display = "flex";
        }
    }

    /**
     * Handle key exchange response (completing the handshake).
     */
    async function handleKeyExchangeResponse(data) {
        const peerName = data.from;
        console.log(`[KeyExchange] Received response key from ${peerName}`);

        const peerPub = await CryptoModule.importPublicKey(data.publicKey);
        const aesKey = await CryptoModule.deriveSharedKey(peerPub);
        sharedKeys[peerName] = aesKey;

        // Resolve pending promise
        if (pendingKeyExchanges[peerName]) {
            pendingKeyExchanges[peerName]();
            delete pendingKeyExchanges[peerName];
        }

        // Update UI
        if (selectedUser === peerName) {
            encryptionBadge.style.display = "flex";
        }
    }

    // -----------------------------------------------------------------------
    // Sending messages
    // -----------------------------------------------------------------------
    async function sendMessage() {
        const text = msgInput.value.trim();
        if (!text || !selectedUser) return;

        // Ensure key exchange is complete
        if (!sharedKeys[selectedUser]) {
            addSystemMessage("🔑 Establishing encrypted connection...");
            await initiateKeyExchange(selectedUser);
            addSystemMessage("✅ Encrypted connection established!");
        }

        // Encrypt
        const { iv, ciphertext } = await CryptoModule.encrypt(sharedKeys[selectedUser], text);
        const timestamp = Date.now();

        ws.send(JSON.stringify({
            type: "encrypted_message",
            target: selectedUser,
            iv,
            ciphertext,
            timestamp,
        }));

        // Add to local history
        if (!messageHistory[selectedUser]) messageHistory[selectedUser] = [];
        messageHistory[selectedUser].push({
            from: currentUser,
            text,
            time: timestamp,
        });

        msgInput.value = "";
        renderMessages();
        scrollToBottom();
    }

    sendBtn.addEventListener("click", sendMessage);
    msgInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // Typing indicator (send)
    let typingSent = false;
    msgInput.addEventListener("input", () => {
        if (!selectedUser || typingSent) return;
        ws.send(JSON.stringify({ type: "typing", target: selectedUser }));
        typingSent = true;
        setTimeout(() => { typingSent = false; }, 2000);
    });

    // -----------------------------------------------------------------------
    // Receiving messages
    // -----------------------------------------------------------------------
    async function handleEncryptedMessage(data) {
        const sender = data.from;

        if (!sharedKeys[sender]) {
            // Key hasn't been exchanged yet — queue message? Should not happen
            // because the sender initiates key exchange first.
            console.warn("[Decrypt] No shared key for", sender);
            return;
        }

        try {
            const plaintext = await CryptoModule.decrypt(sharedKeys[sender], data.iv, data.ciphertext);

            if (!messageHistory[sender]) messageHistory[sender] = [];
            messageHistory[sender].push({
                from: sender,
                text: plaintext,
                time: data.timestamp || Date.now(),
            });

            // If we're viewing this conversation, re-render
            if (selectedUser === sender) {
                renderMessages();
                scrollToBottom();
            }

            // Show notification if viewing another conversation
            if (selectedUser !== sender) {
                showNotification(sender, plaintext);
            }
        } catch (err) {
            console.error("[Decrypt] Failed to decrypt message from", sender, err);
        }
    }

    function handleTypingIndicator(data) {
        if (data.from !== selectedUser) return;
        typingIndicator.classList.add("visible");
        clearTimeout(typingTimers[data.from]);
        typingTimers[data.from] = setTimeout(() => {
            typingIndicator.classList.remove("visible");
        }, 2500);
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------
    function renderMessages() {
        if (!selectedUser) return;
        const msgs = messageHistory[selectedUser] || [];

        if (msgs.length === 0) {
            messagesEl.innerHTML = `
                <div class="empty-chat">
                    <div class="empty-chat-icon">🔐</div>
                    <h3>End-to-End Encrypted</h3>
                    <p>Messages are secured with AES-256-GCM encryption.<br>
                    Send a message to start the conversation.</p>
                </div>`;
            return;
        }

        messagesEl.innerHTML = msgs
            .map((m, i) => {
                const isMine = m.from === currentUser;
                const time = new Date(m.time).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                });
                const showTimeSep = i === 0 || (m.time - msgs[i - 1].time > 300000);
                let html = "";
                if (showTimeSep) {
                    html += `<div class="time-separator"><span>${formatTimeSep(m.time)}</span></div>`;
                }
                html += `
                    <div class="message ${isMine ? "mine" : "theirs"}" style="animation-delay: ${Math.min(i * 0.03, 0.3)}s">
                        <div class="message-bubble">
                            <p>${escapeHtml(m.text)}</p>
                            <span class="message-time">${time}</span>
                        </div>
                    </div>`;
                return html;
            })
            .join("");
    }

    function addSystemMessage(text) {
        if (!selectedUser) return;
        const div = document.createElement("div");
        div.className = "system-message";
        div.textContent = text;
        messagesEl.appendChild(div);
        scrollToBottom();
    }

    function scrollToBottom() {
        requestAnimationFrame(() => {
            messagesEl.scrollTop = messagesEl.scrollHeight;
        });
    }

    function showNotification(from, text) {
        // In-app toast notification
        const toast = document.createElement("div");
        toast.className = "toast-notification";
        toast.innerHTML = `
            <div class="toast-avatar">${from[0].toUpperCase()}</div>
            <div class="toast-content">
                <strong>${escapeHtml(from)}</strong>
                <p>${escapeHtml(text.substring(0, 50))}${text.length > 50 ? "..." : ""}</p>
            </div>`;
        toast.addEventListener("click", () => {
            selectUser(from);
            toast.remove();
        });
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add("visible"), 10);
        setTimeout(() => {
            toast.classList.remove("visible");
            setTimeout(() => toast.remove(), 400);
        }, 4000);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function formatTimeSep(ts) {
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) {
            return "Today " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        }
        return d.toLocaleDateString([], { month: "short", day: "numeric" }) +
            " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }

    // -----------------------------------------------------------------------
    // Boot
    // -----------------------------------------------------------------------
    connect();
})();
