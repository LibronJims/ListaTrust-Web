function showAuthView(viewId) {
    var panels = document.querySelectorAll(".auth-right");
    panels.forEach(function (el) {
        el.classList.add("hidden");
    });
    var target = document.getElementById(viewId);
    if (target) target.classList.remove("hidden");
}

function showDashboard() {
    document.querySelector(".auth-layout").style.display = "none";
    document.getElementById("dashboard").classList.remove("hidden");
    initDashboard();
}

function handleLogin(e) {
    e.preventDefault();
    showDashboard();
    return false;
}

function handleSignup(e) {
    e.preventDefault();
    showDashboard();
    return false;
}

function handleResetPassword(e) {
    e.preventDefault();
    var form = e.target;
    var newP = form.querySelector('[name="newPassword"]').value;
    var confirmP = form.querySelector('[name="confirmPassword"]').value;
    if (newP !== confirmP) {
        alert("Passwords do not match.");
        return false;
    }
    showDashboard();
    return false;
}

function showPage(pageName) {
    // Hide all pages
    var pages = document.querySelectorAll('.page-content');
    pages.forEach(function(page) {
        page.classList.add('hidden');
    });
    
    // Show selected page
    var targetPage = document.getElementById('page-' + pageName);
    if (targetPage) {
        targetPage.classList.remove('hidden');
    }
    
    // Update navigation links
    var navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(function(link) {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === pageName) {
            link.classList.add('active');
        }
    });
    
    // Update notification bell icon (SVG: use class for green)
    var bellLink = document.querySelector('.nav-icon[data-page="notifications"]');
    if (bellLink) {
        if (pageName === 'notifications') bellLink.classList.add('active');
        else bellLink.classList.remove('active');
    }
    // Re-apply search filter on visible page
    var searchInput = document.getElementById('nav-search');
    if (searchInput) filterCards(searchInput.value);
}

// Initialize: show home page by default
function initDashboard() {
    showPage('home');
}

// Filter cards by name (search)
function filterCards(query) {
    var q = (query || '').trim().toLowerCase();
    var visiblePage = document.querySelector('.page-content:not(.hidden)');
    if (!visiblePage) return;
    var cards = visiblePage.querySelectorAll('.debtor-card');
    cards.forEach(function(card) {
        var name = (card.getAttribute('data-name') || '').toLowerCase();
        card.style.display = name.indexOf(q) !== -1 ? '' : 'none';
    });
}
