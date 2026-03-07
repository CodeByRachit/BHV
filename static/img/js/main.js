// Init Theme
const saved = localStorage.getItem('theme') || 'light';
document.documentElement.setAttribute('data-theme', saved);

// Auto Dismiss Alerts
document.addEventListener('DOMContentLoaded', () => {
    const alerts = document.querySelectorAll('.alert');
    if (alerts.length > 0) {
        setTimeout(() => {
            alerts.forEach(alert => {
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-10px)';
                setTimeout(() => { alert.remove(); }, 500);
            });
        }, 10000); 
    }
});

// Theme Logic
function toggleTheme(event) {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'light' ? 'dark' : 'light';

    if (!document.startViewTransition) {
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
        return;
    }

    const x = event.clientX;
    const y = event.clientY;
    const endRadius = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));

    const transition = document.startViewTransition(() => {
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
    });

    transition.ready.then(() => {
        document.documentElement.animate(
            { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${endRadius}px at ${x}px ${y}px)`] },
            { duration: 700, easing: 'cubic-bezier(0.25, 1, 0.5, 1)', pseudoElement: '::view-transition-new(root)' }
        );
    });
}

// Modal Logic
let deleteUrl = '';
function openModal(url) {
    deleteUrl = url;
    document.getElementById('deleteModal').classList.add('active');
}
function closeModal() {
    document.getElementById('deleteModal').classList.remove('active');
}
function confirmDelete() {
    const form = document.getElementById('realDeleteForm');
    form.action = deleteUrl;
    form.submit();
}
window.onclick = function(event) {
    const modal = document.getElementById('deleteModal');
    if (event.target == modal) closeModal();
}