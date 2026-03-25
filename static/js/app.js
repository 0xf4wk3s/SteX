let currentTab = 'passwords';
const ROWS_PER_PAGE = 50;
const paginationState = {};

function switchTab(tabId) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.remove('border-accent', 'text-accent');
        b.classList.add('border-transparent', 'text-gray-500');
    });

    const panel = document.getElementById('panel-' + tabId);
    const btn = document.getElementById('tab-' + tabId);

    if (panel) panel.classList.remove('hidden');
    if (btn) {
        btn.classList.add('border-accent', 'text-accent');
        btn.classList.remove('border-transparent', 'text-gray-500');
    }

    currentTab = tabId;
    applySearch();
}

function applySearch() {
    const query = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();
    const panels = document.querySelectorAll('.tab-panel:not(.hidden)');

    panels.forEach(panel => {
        const rows = panel.querySelectorAll('.data-row');
        let visibleCount = 0;

        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            const match = !query || text.includes(query);
            row.style.display = match ? '' : 'none';
            if (match) visibleCount++;
        });

        updatePagination(panel, visibleCount);
    });
}

function updatePagination(panel, totalVisible) {
    const tableId = panel.querySelector('table')?.id;
    if (!tableId) return;

    let container = panel.querySelector('.pagination-container');
    const rows = Array.from(panel.querySelectorAll('.data-row')).filter(r => r.style.display !== 'none');

    if (rows.length <= ROWS_PER_PAGE) {
        if (container) container.remove();
        rows.forEach(r => r.style.display = '');
        return;
    }

    if (!paginationState[tableId]) {
        paginationState[tableId] = { page: 1 };
    }

    const state = paginationState[tableId];
    const totalPages = Math.ceil(rows.length / ROWS_PER_PAGE);
    state.page = Math.min(state.page, totalPages);

    rows.forEach((row, i) => {
        const start = (state.page - 1) * ROWS_PER_PAGE;
        const end = start + ROWS_PER_PAGE;
        row.style.display = (i >= start && i < end) ? '' : 'none';
    });

    if (!container) {
        container = document.createElement('div');
        container.className = 'pagination-container';
        panel.querySelector('.overflow-x-auto')?.appendChild(container);
    }

    const start = (state.page - 1) * ROWS_PER_PAGE + 1;
    const end = Math.min(state.page * ROWS_PER_PAGE, rows.length);

    container.innerHTML = `
        <span class="text-xs text-gray-500">
            Showing ${start}-${end} of ${rows.length}
        </span>
        <div class="flex gap-1">
            <button class="page-btn" onclick="goToPage('${tableId}', 1)" ${state.page === 1 ? 'disabled' : ''}>
                &laquo;
            </button>
            <button class="page-btn" onclick="goToPage('${tableId}', ${state.page - 1})" ${state.page === 1 ? 'disabled' : ''}>
                &lsaquo;
            </button>
            ${buildPageButtons(tableId, state.page, totalPages)}
            <button class="page-btn" onclick="goToPage('${tableId}', ${state.page + 1})" ${state.page === totalPages ? 'disabled' : ''}>
                &rsaquo;
            </button>
            <button class="page-btn" onclick="goToPage('${tableId}', ${totalPages})" ${state.page === totalPages ? 'disabled' : ''}>
                &raquo;
            </button>
        </div>
    `;
}

function buildPageButtons(tableId, current, total) {
    let pages = [];
    const range = 2;

    for (let i = 1; i <= total; i++) {
        if (i === 1 || i === total || (i >= current - range && i <= current + range)) {
            pages.push(i);
        } else if (pages[pages.length - 1] !== '...') {
            pages.push('...');
        }
    }

    return pages.map(p => {
        if (p === '...') return '<span class="text-gray-600 px-1">...</span>';
        return `<button class="page-btn ${p === current ? 'active' : ''}" onclick="goToPage('${tableId}', ${p})">${p}</button>`;
    }).join('');
}

function goToPage(tableId, page) {
    if (!paginationState[tableId]) return;
    paginationState[tableId].page = page;
    applySearch();
}

function exportCurrentTab(format) {
    if (typeof SESSION_ID === 'undefined') return;

    const tabToDataType = {
        passwords: 'passwords',
        cookies: 'cookies',
        autofills: 'autofills',
        cards: 'cards',
        wallets: 'wallets',
    };

    const dataType = tabToDataType[currentTab];
    if (!dataType) {
        alert('Export is not available for this tab.');
        return;
    }

    window.location.href = `/export/${SESSION_ID}/${dataType}/${format}`;
}

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        let debounce;
        searchInput.addEventListener('input', () => {
            clearTimeout(debounce);
            debounce = setTimeout(applySearch, 200);
        });
    }

    applySearch();
});
