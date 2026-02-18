// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Session Timeout Management
(function () {
    // Configuration
    const SESSION_TIMEOUT_MINUTES = 1; // Must match Program.cs session timeout
    const SESSION_TIMEOUT_MS = SESSION_TIMEOUT_MINUTES * 60 * 1000; // Convert to milliseconds
    const WARNING_TIME_MS = 5 * 1000; // Show warning 5 seconds before timeout
    const COUNTDOWN_INTERVAL_MS = 1000; // Update countdown every second

    let countdownTimer = null;
    let timeoutModal = null;
    let lastActivityTime = null;
    let monitoringInterval = null;
    let warningShown = false;
    let sessionRefreshInterval = null;

    // Initialize on page load
    function initSessionTimeout() {
        // Only initialize if user is authenticated (check for logout button or similar)
        if (!isUserAuthenticated()) {
            return;
        }

        timeoutModal = new bootstrap.Modal(document.getElementById('sessionTimeoutModal'), {
            keyboard: false,
            backdrop: 'static'
        });

        lastActivityTime = Date.now();
        setupActivityListeners();
        startInactivityMonitoring();
    }

    // Check if user is authenticated (find the logout form by rendered action attribute)
    function isUserAuthenticated() {
        return document.querySelector('form[action="/Account/Logout"]') !== null;
    }

    // Setup listeners for user activity
    function setupActivityListeners() {
        document.addEventListener('mousedown', recordActivity);
        document.addEventListener('keydown', recordActivity);
        document.addEventListener('scroll', recordActivity);
        document.addEventListener('touchstart', recordActivity);
        document.addEventListener('click', recordActivity);
    }

    // Record user activity and reset inactivity timer
    function recordActivity() {
        lastActivityTime = Date.now();
        warningShown = false; // Reset warning flag when user is active
    }

    // Start continuous inactivity monitoring (runs regardless of user activity)
    function startInactivityMonitoring() {
        // Check every second if user has been inactive for too long
        monitoringInterval = setInterval(function () {
            if (!isUserAuthenticated()) {
                clearInterval(monitoringInterval);
                return;
            }

            const inactiveTime = Date.now() - lastActivityTime;
            const timeRemaining = SESSION_TIMEOUT_MS - inactiveTime;

            // Check if warning time has been reached or passed
            if (timeRemaining <= WARNING_TIME_MS && timeRemaining > 0 && !warningShown) {
                warningShown = true;
                showTimeoutWarning(timeRemaining);
            }
            // Check if timeout has been reached
            else if (timeRemaining <= 0) {
                // Perform logout immediately
                performLogout();
            }
        }, 1000);
    }

    // Show the timeout warning modal
    function showTimeoutWarning(timeRemaining) {
        if (!timeoutModal) {
            return;
        }

        let remainingSeconds = Math.ceil(timeRemaining / 1000);
        document.getElementById('countdownTimer').textContent = remainingSeconds;

        try {
            timeoutModal.show();
        } catch (e) {
            console.error('Error showing modal:', e);
        }

        // Update countdown every second
        if (countdownTimer) {
            clearInterval(countdownTimer);
        }

        countdownTimer = setInterval(function () {
            remainingSeconds--;
            const element = document.getElementById('countdownTimer');
            if (element) {
                element.textContent = remainingSeconds;
            }

            if (remainingSeconds <= 0) {
                clearInterval(countdownTimer);
            }
        }, COUNTDOWN_INTERVAL_MS);

        // Periodically refresh the server-side session while the warning is shown
        // This prevents the session from expiring if the user was about to continue
        if (sessionRefreshInterval) {
            clearInterval(sessionRefreshInterval);
        }
        sessionRefreshInterval = setInterval(function () {
            fetch('/Account/CheckSessionValid', {
                method: 'GET',
                credentials: 'same-origin'
            }).catch(function(error) {
                console.error('Session keep-alive fetch error:', error);
            });
        }, 2000); // Refresh every 2 seconds while warning is showing
    }

    // Logout user
    function performLogout() {
        // Prevent multiple logout calls
        if (document.body.dataset.loggingOut === 'true') {
            return;
        }
        document.body.dataset.loggingOut = 'true';

        // Clear all intervals
        if (monitoringInterval) {
            clearInterval(monitoringInterval);
        }
        if (countdownTimer) {
            clearInterval(countdownTimer);
        }
        if (sessionRefreshInterval) {
            clearInterval(sessionRefreshInterval);
        }

        // Hide modal and disable user interaction
        if (timeoutModal) {
            try {
                timeoutModal.hide();
            } catch (e) {
                // Modal might not exist; continue anyway
            }
        }
        document.body.style.pointerEvents = 'none';
        document.body.style.opacity = '0.5';

        // Get the anti-forgery token from the logout form if it exists
        const logoutForm = document.querySelector('form[action="/Account/Logout"]');
        let token = null;
        
        if (logoutForm) {
            const tokenInput = logoutForm.querySelector('input[name="__RequestVerificationToken"]');
            if (tokenInput) {
                token = tokenInput.value;
            }
        }

        // Make async POST request to logout endpoint
        const logoutData = new FormData();
        if (token) {
            logoutData.append('__RequestVerificationToken', token);
        }

        fetch('/Account/Logout', {
            method: 'POST',
            credentials: 'same-origin',
            body: logoutData,
            keepalive: true // Ensure request completes even if page unloads
        })
            .then(function (response) {
                // Redirect to login with timeout message
                window.location.href = '/Account/Login?message=SessionExpired';
            })
            .catch(function (error) {
                console.error('Logout error:', error);
                // Fallback: redirect to login anyway
                window.location.href = '/Account/Login?message=SessionExpired';
            });
    }

    // Handle continue session button click
    document.addEventListener('DOMContentLoaded', function () {
        const continueBtn = document.getElementById('continueSessionBtn');
        if (continueBtn) {
            continueBtn.addEventListener('click', function (e) {
                e.preventDefault();
                e.stopPropagation();
                
                // Make a request to the server to refresh server-side session timeout
                fetch('/Account/CheckSessionValid', {
                    method: 'GET',
                    credentials: 'same-origin'
                })
                .then(function(response) {
                    if (response.status === 200) {
                        return response.json();
                    } else if (response.status === 401) {
                        window.location.href = '/Account/Login?message=SessionExpired';
                        return Promise.reject('Session Expired');
                    } else {
                        throw new Error('Failed to refresh session.');
                    }
                })
                .then(function(data) {
                    // Session has been extended on the server side
                    // Now reset the client-side timer to extend the client-side session warning
                    lastActivityTime = Date.now();
                    warningShown = false;

                    // Stop the session keep-alive refresh since user is continuing
                    if (sessionRefreshInterval) {
                        clearInterval(sessionRefreshInterval);
                        sessionRefreshInterval = null;
                    }

                    // Hide the modal
                    if (timeoutModal) {
                        try {
                            timeoutModal.hide();
                        } catch (e) {
                            console.error('Error hiding modal:', e);
                        }
                    }
                })
                .catch(function(error) {
                    if (error !== 'Session Expired') {
                      console.error('Error refreshing session:', error);
                    }
                });
            });
        }

        // Handle logout now button
        const logoutNowBtn = document.getElementById('logoutNowBtn');
        if (logoutNowBtn) {
            logoutNowBtn.addEventListener('click', function () {
                performLogout();
            });
        }

        // Initialize session timeout
        initSessionTimeout();
    });
})();
