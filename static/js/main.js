/**
 * Magnolia Health - Controlled Substance Inventory System
 * Main JavaScript File
 */

// Utility functions
document.addEventListener('DOMContentLoaded', function() {
    // Add dismiss functionality to alerts (no auto-dismiss)
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        // Add dismiss button if not already present
        if (!alert.querySelector('.alert-dismiss')) {
            const dismissBtn = document.createElement('button');
            dismissBtn.className = 'alert-dismiss';
            dismissBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
            dismissBtn.title = 'Dismiss';
            dismissBtn.addEventListener('click', function() {
                alert.style.opacity = '0';
                setTimeout(function() {
                    alert.remove();
                }, 300);
            });
            alert.appendChild(dismissBtn);
        }
    });
    
    // Mobile sidebar toggle
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.querySelector('.sidebar');
    if (menuToggle && sidebar) {
        menuToggle.addEventListener('click', function() {
            sidebar.classList.toggle('open');
        });
    }
    
    // Form validation styling
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
    
    // Confirm delete actions
    const deleteButtons = document.querySelectorAll('[data-confirm]');
    deleteButtons.forEach(function(button) {
        button.addEventListener('click', function(event) {
            const message = this.dataset.confirm || 'Are you sure?';
            if (!confirm(message)) {
                event.preventDefault();
            }
        });
    });
});

// Format numbers with commas
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Format date for display
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}
