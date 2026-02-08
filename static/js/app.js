// === Theme Toggle ===
function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-bs-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-bs-theme', next);
    localStorage.setItem('theme', next);
    updateThemeIcon(next);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// Apply saved theme on load
(function () {
    const saved = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-bs-theme', saved);
    updateThemeIcon(saved);
})();


// === Sidebar Toggle (Mobile) ===
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('show');
}


// === Confirm Modal ===
document.addEventListener('DOMContentLoaded', function () {
    // Initialize DataTables on any table with .datatable class
    if ($.fn.DataTable) {
        $('.datatable').DataTable({
            pageLength: 25,
            order: [[0, 'asc']],
            language: {
                search: '',
                searchPlaceholder: 'Search...',
                lengthMenu: 'Show _MENU_',
            },
        });
    }

    // Confirm modal handler
    document.querySelectorAll('[data-confirm]').forEach(function (el) {
        el.addEventListener('click', function (e) {
            e.preventDefault();
            const message = this.getAttribute('data-confirm');
            const form = this.closest('form');
            const href = this.getAttribute('href');

            document.getElementById('confirmMessage').textContent = message;

            const modal = new bootstrap.Modal(document.getElementById('confirmModal'));
            modal.show();

            document.getElementById('confirmBtn').onclick = function () {
                modal.hide();
                if (form) {
                    form.submit();
                } else if (href) {
                    window.location.href = href;
                }
            };
        });
    });

    // Auto-dismiss flash alerts after 5 seconds
    setTimeout(function () {
        document.querySelectorAll('#flash-container .alert').forEach(function (alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});
