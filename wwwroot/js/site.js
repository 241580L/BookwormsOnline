// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Session Timeout Management
(function () {
    // Configuration
    const SESSION_TIMEOUT_MINUTES = 1; // Must match Program.cs session timeout
    const SESSION_TIMEOUT_MS = SESSION_TIMEOUT_MINUTES * 60 * 1000; // Convert to milliseconds
    const WARNING_TIME_MS = 5 * 1000; // Show warning 5 seconds before timeout
    const COUNTDOWN_INTERVAL_MS = 1000; // Update countdown every second

    let sessionTimeoutTimer = null;
    let warningTimer = null;
    let countdownTimer = null;
    let timeoutModal = null;

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

        setupActivityListeners();
        resetSessionTimeout();
    }

    // Check if user is authenticated
    function isUserAuthenticated() {
        return document.querySelector('form[asp-controller="Account"][asp-action="Logout"]') !== null;
    }

    // Setup listeners for user activity
    function setupActivityListeners() {
        document.addEventListener('mousedown', resetSessionTimeout);
        document.addEventListener('keydown', resetSessionTimeout);
        document.addEventListener('scroll', resetSessionTimeout);
        document.addEventListener('touchstart', resetSessionTimeout);
        document.addEventListener('click', resetSessionTimeout);
    }

    // Reset the session timeout
    function resetSessionTimeout() {
        clearTimeout(sessionTimeoutTimer);
        clearTimeout(warningTimer);
        clearInterval(countdownTimer);

        // Hide modal if visible
        if (timeoutModal) {
            timeoutModal.hide();
            return document.querySelector('form[action="/Account/Logout"]') !== null;
        }

        if (!isUserAuthenticated()) {
            return;
        }

        // Set warning timer (5 seconds before timeout)
        warningTimer = setTimeout(function () {
            showTimeoutWarning();
        }, SESSION_TIMEOUT_MS - WARNING_TIME_MS);

        // Set actual timeout
        sessionTimeoutTimer = setTimeout(function () {
            performLogout();
        }, SESSION_TIMEOUT_MS);
    }

    // Show the timeout warning modal
    function showTimeoutWarning() {
        if (!timeoutModal) {
            return;
        }

        let remainingSeconds = Math.ceil(WARNING_TIME_MS / 1000);
        document.getElementById('countdownTimer').textContent = remainingSeconds;

        timeoutModal.show();

        // Start countdown
        countdownTimer = setInterval(function () {
            remainingSeconds--;
            document.getElementById('countdownTimer').textContent = remainingSeconds;

            if (remainingSeconds <= 0) {
                clearInterval(countdownTimer);
            }
        }, COUNTDOWN_INTERVAL_MS);
    }

    // Logout user
    function performLogout() {
        // Hide modal and disable user interaction
        if (timeoutModal) {
            timeoutModal.hide();
        }
        document.body.style.pointerEvents = 'none';
        document.body.style.opacity = '0.5';
        //const logoutForm = document.querySelector('form[action="/Account/Logout"]');
        const logoutForm = document.querySelector('form[asp-controller="Account"][asp-action="Logout"]');
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
            body: logoutData
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
            continueBtn.addEventListener('click', function () {
                // Make a simple request to refresh the session
                fetch(window.location.href, {
                    method: 'GET',
                    credentials: 'same-origin'
                }).then(function () {
                    resetSessionTimeout();
                }).catch(function (error) {
                    console.error('Error refreshing session:', error);
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
