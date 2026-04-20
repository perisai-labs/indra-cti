// Indra CTI Portal — Feed Browser

let iocs = [];
let filteredIOCs = [];
let currentPage = 1;
const pageSize = 50;
let sortField = 'first_seen';
let sortAscending = false;

/**
 * Initialize feed browser
 */
document.addEventListener('DOMContentLoaded', async () => {
  // Load IOC data
  await initializeStats();
  
  if (allIOCs.length === 0) {
    console.error('Failed to load IOC data');
    return;
  }
  
  iocs = [...allIOCs];
  filteredIOCs = [...iocs];
  
  // Attach event listeners
  document.getElementById('search-input').addEventListener('input', applyFilters);
  document.getElementById('filter-type').addEventListener('change', applyFilters);
  document.getElementById('filter-severity').addEventListener('change', applyFilters);
  document.getElementById('filter-threat-type').addEventListener('change', applyFilters);
  
  // Initial render
  renderTable();
  renderPagination();
  updateResultCount();
});

/**
 * Apply all filters and search
 */
function applyFilters() {
  currentPage = 1;
  
  const searchQuery = document.getElementById('search-input').value;
  const filterType = document.getElementById('filter-type').value;
  const filterSeverity = document.getElementById('filter-severity').value;
  const filterThreatType = document.getElementById('filter-threat-type').value;
  
  // Start with all IOCs
  filteredIOCs = [...iocs];
  
  // Apply search
  if (searchQuery.trim()) {
    const q = searchQuery.toLowerCase();
    filteredIOCs = filteredIOCs.filter(ioc =>
      (ioc.ioc_value || '').toLowerCase().includes(q) ||
      (ioc.threat_name || '').toLowerCase().includes(q) ||
      (ioc.description || '').toLowerCase().includes(q) ||
      (ioc.tags || '').toLowerCase().includes(q)
    );
  }
  
  // Apply type filter
  if (filterType) {
    filteredIOCs = filteredIOCs.filter(ioc =>
      (ioc.ioc_type || '').toLowerCase() === filterType.toLowerCase()
    );
  }
  
  // Apply severity filter
  if (filterSeverity) {
    filteredIOCs = filteredIOCs.filter(ioc =>
      (ioc.severity || '').toLowerCase() === filterSeverity.toLowerCase()
    );
  }
  
  // Apply threat type filter
  if (filterThreatType) {
    filteredIOCs = filteredIOCs.filter(ioc =>
      (ioc.threat_type || '').toLowerCase().includes(filterThreatType.toLowerCase())
    );
  }
  
  // Apply sort
  applySort();
  
  // Render
  updateResultCount();
  renderTable();
  renderPagination();
}

/**
 * Sort table by field
 * @param {string} field - Field to sort
 */
function sortTable(field) {
  if (sortField === field) {
    sortAscending = !sortAscending;
  } else {
    sortField = field;
    sortAscending = false;
  }
  
  applySort();
  currentPage = 1;
  renderTable();
  renderPagination();
}

/**
 * Apply sort to filtered IOCs
 */
function applySort() {
  filteredIOCs.sort((a, b) => {
    let aVal = (a[sortField] || '').toString().toLowerCase();
    let bVal = (b[sortField] || '').toString().toLowerCase();
    
    // Try numeric sort for severity/dates
    const aNum = parseFloat(aVal);
    const bNum = parseFloat(bVal);
    if (!isNaN(aNum) && !isNaN(bNum)) {
      return sortAscending ? aNum - bNum : bNum - aNum;
    }
    
    // String sort
    const result = aVal.localeCompare(bVal);
    return sortAscending ? result : -result;
  });
}

/**
 * Render IOC table for current page
 */
function renderTable() {
  const paginatedData = paginate(filteredIOCs, currentPage, pageSize);
  const tbody = document.getElementById('ioc-tbody');
  
  if (paginatedData.items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: var(--spacing-lg);">No IOCs found matching your filters.</td></tr>';
    return;
  }
  
  tbody.innerHTML = paginatedData.items.map(ioc => {
    const severity = (ioc.severity || 'informational').toLowerCase();
    const badgeClass = `badge badge-${severity}`;
    const mitreLink = ioc.mitre_attack ? 
      `<a href="https://attack.mitre.org/techniques/${ioc.mitre_attack}/" target="_blank">${ioc.mitre_attack}</a>` :
      '-';
    
    return `
      <tr>
        <td><code style="font-size: 0.85rem;">${escapeHtml(ioc.ioc_type || 'unknown')}</code></td>
        <td style="word-break: break-all; max-width: 300px;">
          <code style="font-size: 0.85rem; cursor: pointer; padding: var(--spacing-xs); border-radius: 4px; background-color: var(--bg-base); display: inline-block;" onclick="copyToClipboard('${escapeHtml(ioc.ioc_value)}', this)" title="Click to copy">
            ${truncate(escapeHtml(ioc.ioc_value || '-'), 40)}
          </code>
        </td>
        <td><span title="${escapeHtml(ioc.threat_name || '')}">${truncate(escapeHtml(ioc.threat_name || '-'), 30)}</span></td>
        <td>${escapeHtml(ioc.threat_type || '-')}</td>
        <td><span class="${badgeClass}">${severity}</span></td>
        <td>${formatDate(ioc.first_seen || '')}</td>
        <td style="font-size: 0.9rem;">${mitreLink}</td>
      </tr>
    `;
  }).join('');
}

/**
 * Render pagination controls
 */
function renderPagination() {
  const paginatedData = paginate(filteredIOCs, currentPage, pageSize);
  const paginationEl = document.getElementById('pagination');
  
  let html = '';
  
  // Previous button
  if (paginatedData.hasPrev) {
    html += `<a onclick="goToPage(${currentPage - 1})" style="cursor: pointer;">← Prev</a>`;
  } else {
    html += '<span class="disabled">← Prev</span>';
  }
  
  // Page numbers
  const maxPages = Math.min(paginatedData.pages, 5);
  let startPage = Math.max(1, currentPage - 2);
  let endPage = Math.min(paginatedData.pages, startPage + 4);
  
  if (endPage - startPage < 4) {
    startPage = Math.max(1, endPage - 4);
  }
  
  if (startPage > 1) {
    html += `<a onclick="goToPage(1)" style="cursor: pointer;">1</a>`;
    if (startPage > 2) html += '<span>...</span>';
  }
  
  for (let i = startPage; i <= endPage; i++) {
    if (i === currentPage) {
      html += `<span class="active">${i}</span>`;
    } else {
      html += `<a onclick="goToPage(${i})" style="cursor: pointer;">${i}</a>`;
    }
  }
  
  if (endPage < paginatedData.pages) {
    if (endPage < paginatedData.pages - 1) html += '<span>...</span>';
    html += `<a onclick="goToPage(${paginatedData.pages})" style="cursor: pointer;">${paginatedData.pages}</a>`;
  }
  
  // Next button
  if (paginatedData.hasNext) {
    html += `<a onclick="goToPage(${currentPage + 1})" style="cursor: pointer;">Next →</a>`;
  } else {
    html += '<span class="disabled">Next →</span>';
  }
  
  paginationEl.innerHTML = html;
}

/**
 * Go to page
 * @param {number} page - Page number
 */
function goToPage(page) {
  const paginatedData = paginate(filteredIOCs, 1, pageSize);
  if (page > 0 && page <= paginatedData.pages) {
    currentPage = page;
    renderTable();
    renderPagination();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    updatePageInfo();
  }
}

/**
 * Update result count display
 */
function updateResultCount() {
  const paginatedData = paginate(filteredIOCs, 1, pageSize);
  document.getElementById('result-count').textContent = paginatedData.total.toLocaleString();
  updatePageInfo();
}

/**
 * Update page info display
 */
function updatePageInfo() {
  const paginatedData = paginate(filteredIOCs, currentPage, pageSize);
  if (paginatedData.total === 0) {
    document.getElementById('page-info').textContent = '';
    return;
  }
  
  const start = (currentPage - 1) * pageSize + 1;
  const end = Math.min(currentPage * pageSize, paginatedData.total);
  document.getElementById('page-info').textContent = 
    `Page ${currentPage} of ${paginatedData.pages} • Showing ${start}–${end} of ${paginatedData.total.toLocaleString()}`;
}

/**
 * Truncate text with ellipsis
 * @param {string} text - Text to truncate
 * @param {number} length - Max length
 * @returns {string} Truncated text
 */
function truncate(text, length) {
  if (text.length > length) {
    return text.substring(0, length) + '…';
  }
  return text;
}
