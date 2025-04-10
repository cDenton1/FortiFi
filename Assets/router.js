// Handle page navigation
document.querySelectorAll('.sidebar-icon').forEach(icon => {
    icon.addEventListener('click', (e) => {
        const page = e.target.dataset.page;
        window.location.hash = page;
    });
});

// Route handler
function handleRoute() {
    const pages = ['dashboard', 'devices', 'traffic', 'alerts', 'config'];
    const hash = window.location.hash.substring(1) || 'dashboard';

    pages.forEach(page => {
        const element = document.getElementById(`${page}-page`);
        element.classList.toggle('hidden', page !== hash);
    });
}

// Initial load and hash change
window.addEventListener('load', handleRoute);
window.addEventListener('hashchange', handleRoute);