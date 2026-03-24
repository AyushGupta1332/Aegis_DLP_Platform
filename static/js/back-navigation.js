/**
 * Aegis DLP - Back Navigation with Scroll Position Preservation
 * 
 * This module handles:
 * 1. Saving scroll position before navigating away
 * 2. Restoring scroll position when returning to a page
 * 3. Smart back navigation using browser history
 */

(function() {
    'use strict';

    const SCROLL_STORAGE_KEY = 'aegis_scroll_positions';
    const MAX_STORED_PAGES = 10;

    /**
     * Get current page identifier
     */
    function getPageKey() {
        return window.location.pathname + window.location.search;
    }

    /**
     * Get all stored scroll positions
     */
    function getScrollPositions() {
        try {
            const data = sessionStorage.getItem(SCROLL_STORAGE_KEY);
            return data ? JSON.parse(data) : {};
        } catch (e) {
            return {};
        }
    }

    /**
     * Save scroll position for current page
     */
    function saveScrollPosition() {
        const positions = getScrollPositions();
        const pageKey = getPageKey();
        
        positions[pageKey] = {
            x: window.scrollX || window.pageXOffset,
            y: window.scrollY || window.pageYOffset,
            timestamp: Date.now()
        };

        // Clean up old entries if we have too many
        const keys = Object.keys(positions);
        if (keys.length > MAX_STORED_PAGES) {
            const sortedKeys = keys.sort((a, b) => positions[a].timestamp - positions[b].timestamp);
            const keysToRemove = sortedKeys.slice(0, keys.length - MAX_STORED_PAGES);
            keysToRemove.forEach(key => delete positions[key]);
        }

        try {
            sessionStorage.setItem(SCROLL_STORAGE_KEY, JSON.stringify(positions));
        } catch (e) {
            console.warn('Could not save scroll position:', e);
        }
    }

    /**
     * Restore scroll position for current page
     */
    function restoreScrollPosition() {
        const positions = getScrollPositions();
        const pageKey = getPageKey();
        const position = positions[pageKey];

        if (position) {
            // Use requestAnimationFrame to ensure DOM is ready
            requestAnimationFrame(() => {
                window.scrollTo({
                    left: position.x,
                    top: position.y,
                    behavior: 'instant'
                });
            });
        }
    }

    /**
     * Navigate back using browser history
     */
    function navigateBack() {
        // Save current scroll position before going back
        saveScrollPosition();
        
        // Check if there's actually history to go back to
        if (window.history.length > 1) {
            window.history.back();
        } else {
            // Fallback to home page if no history
            window.location.href = '/';
        }
    }

    /**
     * Initialize scroll position management
     */
    function init() {
        // Restore scroll position on page load
        if (performance.navigation.type === 2 || 
            (window.performance.getEntriesByType && 
             window.performance.getEntriesByType('navigation')[0]?.type === 'back_forward')) {
            // Page loaded via back/forward navigation
            restoreScrollPosition();
        }

        // Save scroll position before page unload
        window.addEventListener('beforeunload', saveScrollPosition);

        // Also save on visibility change (for mobile)
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'hidden') {
                saveScrollPosition();
            }
        });

        // Attach click handler to all back buttons
        document.querySelectorAll('[data-back-button]').forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                navigateBack();
            });
        });

        // Also check for pageshow event (works better for bfcache)
        window.addEventListener('pageshow', (event) => {
            if (event.persisted) {
                // Page was restored from bfcache
                restoreScrollPosition();
            }
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose to global scope for inline onclick handlers
    window.AegisDLP = window.AegisDLP || {};
    window.AegisDLP.navigateBack = navigateBack;
    window.AegisDLP.saveScrollPosition = saveScrollPosition;
    window.AegisDLP.restoreScrollPosition = restoreScrollPosition;

})();
