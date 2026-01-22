/**
 * SentinelX AI Chatbot Widget
 * Floating chatbot interface with real-time chat capabilities
 */

class ChatbotWidget {
    constructor() {
        this.userId = 'user_' + Math.random().toString(36).substr(2, 9);
        this.isOpen = false;
        this.isLoading = false;
        this.socket = null;
        this.messageHistory = [];
        this.pageContext = this.getPageContext();

        this.init();
    }

    getPageContext() {
        // Detect current page and extract relevant context
        const path = window.location.pathname;
        const context = { page: path };

        // Check for global page context set by templates
        if (window.SENTINELX_PAGE_CONTEXT) {
            return { ...context, ...window.SENTINELX_PAGE_CONTEXT };
        }

        // Auto-detect page type from URL
        if (path.includes('/phishing/email/')) {
            context.page_type = 'email_details';
        } else if (path.includes('/phishing')) {
            context.page_type = 'phishing';
        } else if (path.includes('/data-classification')) {
            context.page_type = 'classification';
        } else if (path.includes('/anomaly')) {
            context.page_type = 'anomaly';
        } else if (path.includes('/encryption')) {
            context.page_type = 'encryption';
        }

        return context;
    }


    init() {
        this.createWidget();
        this.attachEventListeners();
        this.initSocketIO();
        this.loadHistory();
    }

    createWidget() {
        const widget = document.createElement('div');
        widget.className = 'chatbot-widget';
        widget.innerHTML = `
            <!-- Toggle Button -->
            <button class="chatbot-toggle" id="chatbot-toggle" title="SentinelX AI Assistant">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
            </button>
            
            <!-- Chat Window -->
            <div class="chatbot-window" id="chatbot-window">
                <!-- Header -->
                <div class="chatbot-header">
                    <div class="chatbot-header-icon">
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
                        </svg>
                    </div>
                    <div class="chatbot-header-info">
                        <h3 class="chatbot-header-title">SentinelX AI</h3>
                        <div class="chatbot-header-status">
                            <span class="dot"></span>
                            <span>Security Assistant</span>
                        </div>
                    </div>
                    <button class="chatbot-clear-btn" id="chatbot-clear" title="Clear conversation">
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                        </svg>
                    </button>
                </div>
                
                <!-- Messages -->
                <div class="chatbot-messages" id="chatbot-messages">
                    <div class="chatbot-message assistant">
                        👋 Hello! I'm your SentinelX Security AI Assistant. I can help you with:
                        <ul>
                            <li>Network anomaly detection status</li>
                            <li>Phishing email analysis</li>
                            <li>Data classification results</li>
                            <li>Security recommendations</li>
                        </ul>
                        How can I assist you today?
                    </div>
                </div>
                
                <!-- Input Area -->
                <div class="chatbot-input-area">
                    <input type="text" class="chatbot-input" id="chatbot-input" 
                           placeholder="Ask about security..." maxlength="500">
                    <button class="chatbot-send-btn" id="chatbot-send" title="Send message">
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
                        </svg>
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(widget);

        // Store references
        this.elements = {
            toggle: document.getElementById('chatbot-toggle'),
            window: document.getElementById('chatbot-window'),
            messages: document.getElementById('chatbot-messages'),
            input: document.getElementById('chatbot-input'),
            sendBtn: document.getElementById('chatbot-send'),
            clearBtn: document.getElementById('chatbot-clear')
        };
    }

    attachEventListeners() {
        // Toggle chat window
        this.elements.toggle.addEventListener('click', () => this.toggleChat());

        // Send message
        this.elements.sendBtn.addEventListener('click', () => this.sendMessage());

        // Enter key to send
        this.elements.input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Clear conversation
        this.elements.clearBtn.addEventListener('click', () => this.clearConversation());
    }

    initSocketIO() {
        // Check if Socket.IO is available
        if (typeof io !== 'undefined') {
            this.socket = io();

            this.socket.on('connect', () => {
                console.log('Chatbot connected to server');
                this.socket.emit('join_chat', { user_id: this.userId });
            });

            this.socket.on('chat_status', (data) => {
                // Show typing status updates
                this.showTypingIndicator(data.message);
            });

            // Note: We use API fetch for responses, not SocketIO, to avoid duplicates
        }
    }

    toggleChat() {
        this.isOpen = !this.isOpen;
        this.elements.window.classList.toggle('open', this.isOpen);
        this.elements.toggle.classList.toggle('active', this.isOpen);

        if (this.isOpen) {
            this.elements.input.focus();
        }
    }

    async sendMessage() {
        const message = this.elements.input.value.trim();
        if (!message || this.isLoading) return;

        // Add user message
        this.addMessage(message, 'user');
        this.elements.input.value = '';

        // Show loading state
        this.isLoading = true;
        this.elements.sendBtn.disabled = true;
        this.showTypingIndicator('Thinking...');

        // Refresh page context before each message (in case it wasn't loaded initially)
        this.pageContext = this.getPageContext();
        console.log('Sending with page context:', this.pageContext);

        // Send via API
        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: message,
                    user_id: this.userId,
                    page_context: this.pageContext
                })
            });

            const data = await response.json();
            this.hideTypingIndicator();

            if (data.status === 'success') {
                this.addMessage(data.response, 'assistant');
            } else {
                this.addMessage('⚠️ ' + (data.message || 'An error occurred'), 'assistant');
            }
        } catch (error) {
            this.hideTypingIndicator();
            this.addMessage('⚠️ Connection error. Please try again.', 'assistant');
        }

        this.isLoading = false;
        this.elements.sendBtn.disabled = false;
    }

    addMessage(content, type) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `chatbot-message ${type}`;

        // Simple markdown-like formatting
        let formattedContent = content
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/\n/g, '<br>');

        // Convert bullet points
        formattedContent = formattedContent.replace(/^- (.*?)(<br>|$)/gm, '<li>$1</li>');
        if (formattedContent.includes('<li>')) {
            formattedContent = formattedContent.replace(/(<li>.*<\/li>)+/g, '<ul>$&</ul>');
        }

        messageDiv.innerHTML = formattedContent;
        this.elements.messages.appendChild(messageDiv);

        // Scroll to bottom
        this.elements.messages.scrollTop = this.elements.messages.scrollHeight;

        // Store in history
        this.messageHistory.push({ type, content });
    }

    showTypingIndicator(status) {
        this.hideTypingIndicator();

        const typingDiv = document.createElement('div');
        typingDiv.className = 'chatbot-typing';
        typingDiv.id = 'chatbot-typing';
        typingDiv.innerHTML = `
            <span></span>
            <span></span>
            <span></span>
        `;
        this.elements.messages.appendChild(typingDiv);
        this.elements.messages.scrollTop = this.elements.messages.scrollHeight;
    }

    hideTypingIndicator() {
        const typing = document.getElementById('chatbot-typing');
        if (typing) typing.remove();
    }

    async clearConversation() {
        // Clear UI
        this.elements.messages.innerHTML = `
            <div class="chatbot-message assistant">
                👋 Conversation cleared. How can I help you with security?
            </div>
        `;
        this.messageHistory = [];

        // Clear on server
        try {
            await fetch('/api/chat/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: this.userId })
            });
        } catch (error) {
            console.log('Could not clear server history');
        }
    }

    async loadHistory() {
        try {
            const response = await fetch(`/api/chat/history?user_id=${this.userId}`);
            const data = await response.json();

            if (data.history && data.history.length > 0) {
                data.history.forEach(msg => {
                    this.addMessage(msg.content, msg.role === 'user' ? 'user' : 'assistant');
                });
            }
        } catch (error) {
            console.log('Could not load history');
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new ChatbotWidget());
} else {
    new ChatbotWidget();
}

// Global activity logging helper
window.SentinelXActivity = {
    /**
     * Log a security activity for the current user
     * @param {string} activityType - Type of activity (anomaly_scan, classification, phishing_scan, encryption)
     * @param {string} summary - Human-readable summary
     * @param {object} details - Optional details object with metrics
     */
    log: async function (activityType, summary, details = {}) {
        // Get user ID from chatbot widget or use default
        const userId = window.chatbotWidget?.userId || 'default';

        try {
            const response = await fetch('/api/activity/log', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: userId,
                    activity_type: activityType,
                    summary: summary,
                    details: details
                })
            });

            const data = await response.json();
            if (data.status === 'success') {
                console.log('📝 Activity logged:', activityType, summary);
            }
            return data;
        } catch (error) {
            console.warn('Failed to log activity:', error);
            return { status: 'error', message: error.message };
        }
    },

    /**
     * Log an anomaly detection activity
     */
    logAnomalyScan: function (totalSamples, normalCount, anomalyCount) {
        return this.log('anomaly_scan',
            `Analyzed ${totalSamples} network samples: ${normalCount} normal, ${anomalyCount} anomalies detected`,
            { total_samples: totalSamples, normal: normalCount, anomalies: anomalyCount }
        );
    },

    /**
     * Log a data classification activity
     */
    logClassification: function (totalFiles, sensitiveCount, categories) {
        return this.log('classification',
            `Scanned ${totalFiles} files: ${sensitiveCount} marked as sensitive`,
            { total_files: totalFiles, sensitive: sensitiveCount, categories: categories }
        );
    },

    /**
     * Log a phishing detection activity
     */
    logPhishingScan: function (totalEmails, safeCount, phishingCount) {
        return this.log('phishing_scan',
            `Analyzed ${totalEmails} emails: ${safeCount} safe, ${phishingCount} phishing detected`,
            { total_emails: totalEmails, safe: safeCount, phishing: phishingCount }
        );
    },

    /**
     * Log an encryption activity
     */
    logEncryption: function (action, fileName, options = {}) {
        const summary = action === 'encrypt'
            ? `Encrypted file "${fileName}"${options.viewOnly ? ' (view-only mode)' : ''}`
            : `Decrypted file "${fileName}"`;
        return this.log('encryption', summary, { action, fileName, ...options });
    }
};
