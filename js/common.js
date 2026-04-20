// Indra CTI Portal — Common Utilities

/**
 * CSV Parser — converts CSV text to array of objects
 * @param {string} csv - CSV content
 * @returns {array} Array of objects (rows)
 */
function parseCSV(csv) {
  const lines = csv.trim().split('\n');
  if (lines.length < 2) return [];
  
  const headerLine = lines[0];
  const headers = headerLine.split(',').map(h => h.trim().toLowerCase());
  
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    // Simple CSV parse (handles quoted fields)
    const values = [];
    let current = '';
    let inQuotes = false;
    
    for (let j = 0; j < line.length; j++) {
      const char = line[j];
      const nextChar = line[j + 1];
      
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        values.push(current.trim().replace(/^"+|"+$/g, ''));
        current = '';
      } else {
        current += char;
      }
    }
    values.push(current.trim().replace(/^"+|"+$/g, ''));
    
    const row = {};
    headers.forEach((header, idx) => {
      row[header] = values[idx] || '';
    });
    rows.push(row);
  }
  
  return rows;
}

/**
 * Fetch CSV from raw GitHub URL
 * @param {string} url - GitHub raw content URL
 * @returns {Promise<array>} Parsed CSV data
 */
async function fetchCSV(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    return parseCSV(text);
  } catch (error) {
    console.error('Failed to fetch CSV:', error);
    return [];
  }
}

/**
 * Highlight active navigation link
 */
function highlightActiveNav() {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  const navLinks = document.querySelectorAll('.nav-links a');
  
  navLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPage || (currentPage === '' && href === 'index.html')) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @param {HTMLElement} element - Optional: element to show feedback
 */
function copyToClipboard(text, element = null) {
  navigator.clipboard.writeText(text).then(() => {
    if (element) {
      const originalText = element.textContent;
      element.textContent = '✓ Copied!';
      element.style.color = 'var(--color-primary)';
      setTimeout(() => {
        element.textContent = originalText;
        element.style.color = '';
      }, 2000);
    }
  }).catch(err => {
    console.error('Clipboard copy failed:', err);
  });
}

/**
 * Format date to YYYY-MM-DD
 * @param {string|Date} date - Date to format
 * @returns {string} Formatted date
 */
function formatDate(date) {
  if (typeof date === 'string') {
    return date; // Assume already formatted
  }
  const d = new Date(date);
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${d.getFullYear()}-${month}-${day}`;
}

/**
 * Severity score helper
 * @param {string} severity - Severity level
 * @returns {number} Score (4=critical, 3=high, 2=medium, 1=low, 0=info)
 */
function severityScore(severity) {
  const s = (severity || '').toLowerCase();
  const scores = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'informational': 0,
    'info': 0
  };
  return scores[s] !== undefined ? scores[s] : 0;
}

/**
 * Search across multiple fields
 * @param {array} items - Data array
 * @param {string} query - Search term
 * @param {array} fields - Fields to search in
 * @returns {array} Filtered items
 */
function searchItems(items, query, fields) {
  if (!query.trim()) return items;
  
  const q = query.toLowerCase();
  return items.filter(item => {
    return fields.some(field => {
      const value = (item[field] || '').toLowerCase();
      return value.includes(q);
    });
  });
}

/**
 * Filter items by field value
 * @param {array} items - Data array
 * @param {string} field - Field to filter
 * @param {string} value - Filter value (empty = no filter)
 * @returns {array} Filtered items
 */
function filterItems(items, field, value) {
  if (!value || value === 'all') return items;
  return items.filter(item => {
    const itemValue = (item[field] || '').toLowerCase();
    return itemValue === value.toLowerCase();
  });
}

/**
 * Sort items by field
 * @param {array} items - Data array
 * @param {string} field - Field to sort
 * @param {boolean} ascending - Sort direction (default: true)
 * @returns {array} Sorted items
 */
function sortItems(items, field, ascending = true) {
  return [...items].sort((a, b) => {
    const aVal = (a[field] || '').toString().toLowerCase();
    const bVal = (b[field] || '').toString().toLowerCase();
    
    // Try numeric sort if both look like numbers
    const aNum = parseFloat(aVal);
    const bNum = parseFloat(bVal);
    if (!isNaN(aNum) && !isNaN(bNum)) {
      return ascending ? aNum - bNum : bNum - aNum;
    }
    
    // String sort
    if (ascending) {
      return aVal.localeCompare(bVal);
    } else {
      return bVal.localeCompare(aVal);
    }
  });
}

/**
 * Paginate array
 * @param {array} items - Data array
 * @param {number} page - Current page (1-indexed)
 * @param {number} pageSize - Items per page
 * @returns {object} { items, total, pages, currentPage }
 */
function paginate(items, page = 1, pageSize = 50) {
  const total = items.length;
  const pages = Math.ceil(total / pageSize);
  const p = Math.max(1, Math.min(page, pages));
  const start = (p - 1) * pageSize;
  const end = start + pageSize;
  
  return {
    items: items.slice(start, end),
    total,
    pages,
    currentPage: p,
    hasNext: p < pages,
    hasPrev: p > 1
  };
}

/**
 * Export data as JSON
 * @param {array} data - Data to export
 * @param {string} filename - Output filename
 */
function exportJSON(data, filename = 'data.json') {
  const json = JSON.stringify(data, null, 2);
  downloadFile(json, filename, 'application/json');
}

/**
 * Export data as CSV
 * @param {array} data - Data to export
 * @param {string} filename - Output filename
 */
function exportCSV(data, filename = 'data.csv') {
  if (data.length === 0) return;
  
  const headers = Object.keys(data[0]);
  const csv = [headers.join(',')];
  
  data.forEach(row => {
    const values = headers.map(h => {
      const val = row[h] || '';
      // Escape quotes and wrap if contains comma/quote
      if (val.includes(',') || val.includes('"')) {
        return `"${val.replace(/"/g, '""')}"`;
      }
      return val;
    });
    csv.push(values.join(','));
  });
  
  downloadFile(csv.join('\n'), filename, 'text/csv');
}

/**
 * Download file as blob
 * @param {string} content - File content
 * @param {string} filename - Filename
 * @param {string} mimeType - MIME type
 */
function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Convert IOC data to STIX 2.1 (simplified)
 * @param {array} iocs - IOC array
 * @returns {object} STIX Bundle
 */
function toSTIX2(iocs) {
  const objects = [
    {
      type: 'bundle',
      id: 'bundle--' + generateUUID(),
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      objects: iocs.map(ioc => ({
        type: 'indicator',
        id: 'indicator--' + generateUUID(),
        created: ioc.first_seen || new Date().toISOString(),
        modified: ioc.last_seen || new Date().toISOString(),
        pattern: `[${mapIOCTypeToSTIX(ioc.ioc_type)} = '${ioc.ioc_value}']`,
        labels: ['malicious-activity'],
        name: ioc.threat_name || 'Unknown',
        description: ioc.description || '',
        valid_from: ioc.first_seen || new Date().toISOString(),
        kill_chain_phases: ioc.mitre_attack ? [{
          kill_chain_name: 'mitre-attack',
          phase_name: ioc.mitre_attack
        }] : []
      }))
    }
  ];
  
  return objects[0];
}

/**
 * Map IOC type to STIX pattern
 * @param {string} type - IOC type
 * @returns {string} STIX pattern prefix
 */
function mapIOCTypeToSTIX(type) {
  const mapping = {
    'hash-md5': 'file:hashes.MD5',
    'hash-sha256': 'file:hashes.SHA-256',
    'ip': 'ipv4-addr:value',
    'domain': 'domain-name:value',
    'url': 'url:value',
    'email': 'email-addr:value',
    'filename': 'file:name'
  };
  return mapping[type] || 'file:name';
}

/**
 * Simple UUID generator
 * @returns {string} UUID v4-like string
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * Initialize page on load
 */
document.addEventListener('DOMContentLoaded', () => {
  highlightActiveNav();
});
