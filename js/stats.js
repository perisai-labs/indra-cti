// Indra CTI Portal — Statistics & Dashboard

const CSV_BASE = 'https://raw.githubusercontent.com/perisai-labs/indra-cti/master/feeds/';
const IOCS_URL = CSV_BASE + 'ioc-all.csv';

let allIOCs = [];
let activityChart = null;

/**
 * Initialize statistics and load IOC data
 */
async function initializeStats() {
  try {
    // Fetch IOC data from GitHub
    allIOCs = await fetchCSV(IOCS_URL);
    
    if (allIOCs.length === 0) {
      console.warn('No IOC data loaded');
      return;
    }
    
    // Update stats cards
    updateStatsCards();
    
    // Populate recent threats table
    populateRecentTable();
    
    // Initialize activity chart if canvas exists
    if (document.getElementById('activity-chart')) {
      initActivityChart();
    }
  } catch (error) {
    console.error('Error initializing stats:', error);
  }
}

/**
 * Update statistics cards with IOC counts
 */
function updateStatsCards() {
  const totalIOCs = allIOCs.length;
  const aptCount = allIOCs.filter(ioc => 
    (ioc.threat_type || '').toLowerCase().includes('apt')
  ).length;
  const malwareCount = allIOCs.filter(ioc => 
    (ioc.threat_type || '').toLowerCase().includes('malware')
  ).length;
  const ransomwareCount = allIOCs.filter(ioc => 
    (ioc.threat_type || '').toLowerCase().includes('ransomware')
  ).length;
  
  // Update DOM
  const totalEl = document.getElementById('total-iocs');
  const aptEl = document.getElementById('apt-count');
  const malwareEl = document.getElementById('malware-count');
  const ransomwareEl = document.getElementById('ransomware-count');
  
  if (totalEl) totalEl.textContent = totalIOCs.toLocaleString();
  if (aptEl) aptEl.textContent = aptCount.toLocaleString();
  if (malwareEl) malwareEl.textContent = malwareCount.toLocaleString();
  if (ransomwareEl) ransomwareEl.textContent = ransomwareCount.toLocaleString();
}

/**
 * Populate recent threats table with last N IOCs
 * @param {number} limit - Number of recent items to show
 */
function populateRecentTable(limit = 10) {
  const tbody = document.getElementById('recent-tbody');
  if (!tbody) return;
  
  // Sort by last_seen (most recent first)
  const sorted = [...allIOCs].sort((a, b) => {
    const dateA = new Date(a.last_seen || 0);
    const dateB = new Date(b.last_seen || 0);
    return dateB - dateA;
  });
  
  const recent = sorted.slice(0, limit);
  
  tbody.innerHTML = recent.map(ioc => {
    const severity = (ioc.severity || 'informational').toLowerCase();
    const badgeClass = `badge badge-${severity}`;
    
    return `
      <tr>
        <td><code style="font-size: 0.85rem;">${escapeHtml(ioc.ioc_type || 'unknown')}</code></td>
        <td style="word-break: break-all; max-width: 250px;">
          <code style="font-size: 0.85rem; cursor: pointer;" onclick="copyToClipboard('${escapeHtml(ioc.ioc_value)}', this)">
            ${escapeHtml(ioc.ioc_value || '-')}
          </code>
        </td>
        <td>${escapeHtml(ioc.threat_name || '-')}</td>
        <td>${escapeHtml(ioc.threat_type || '-')}</td>
        <td><span class="${badgeClass}">${severity}</span></td>
        <td>${formatDate(ioc.first_seen || '')}</td>
      </tr>
    `;
  }).join('');
}

/**
 * Initialize activity chart showing IOCs over time (last 30 days)
 */
function initActivityChart() {
  const canvas = document.getElementById('activity-chart');
  if (!canvas) return;
  
  // Group IOCs by date (using first_seen)
  const dateMap = {};
  
  allIOCs.forEach(ioc => {
    if (!ioc.first_seen) return;
    
    const date = ioc.first_seen.split(' ')[0]; // Extract date part
    if (!dateMap[date]) {
      dateMap[date] = {
        total: 0,
        apt: 0,
        malware: 0,
        ransomware: 0
      };
    }
    
    dateMap[date].total++;
    
    const threatType = (ioc.threat_type || '').toLowerCase();
    if (threatType.includes('apt')) dateMap[date].apt++;
    if (threatType.includes('malware')) dateMap[date].malware++;
    if (threatType.includes('ransomware')) dateMap[date].ransomware++;
  });
  
  // Sort by date and limit to last 30 days
  const sorted = Object.entries(dateMap)
    .sort(([dateA], [dateB]) => dateA.localeCompare(dateB))
    .slice(-30);
  
  const labels = sorted.map(([date]) => date);
  const totalData = sorted.map(([, data]) => data.total);
  const aptData = sorted.map(([, data]) => data.apt);
  const malwareData = sorted.map(([, data]) => data.malware);
  const ransomwareData = sorted.map(([, data]) => data.ransomware);
  
  // Destroy existing chart if any
  if (activityChart) {
    activityChart.destroy();
  }
  
  activityChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Total IOCs',
          data: totalData,
          borderColor: '#00ff88',
          backgroundColor: 'rgba(0, 255, 136, 0.1)',
          borderWidth: 2,
          tension: 0.4,
          fill: true
        },
        {
          label: 'Malware',
          data: malwareData,
          borderColor: '#ff4757',
          backgroundColor: 'rgba(255, 71, 87, 0.05)',
          borderWidth: 2,
          tension: 0.4,
          fill: false
        },
        {
          label: 'Ransomware',
          data: ransomwareData,
          borderColor: '#ffa502',
          backgroundColor: 'rgba(255, 165, 2, 0.05)',
          borderWidth: 2,
          tension: 0.4,
          fill: false
        },
        {
          label: 'APT',
          data: aptData,
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0, 212, 255, 0.05)',
          borderWidth: 2,
          tension: 0.4,
          fill: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: '#e8eaf6',
            font: { family: "'Inter', sans-serif", size: 12, weight: '500' }
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: '#1e2446' },
          ticks: { color: '#8b8fac' }
        },
        x: {
          grid: { display: false },
          ticks: { color: '#8b8fac', maxRotation: 45 }
        }
      }
    }
  });
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return (text || '').replace(/[&<>"']/g, m => map[m]);
}

/**
 * Get unique values from a field
 * @param {array} items - Data array
 * @param {string} field - Field name
 * @returns {array} Unique sorted values
 */
function getUniqueValues(items, field) {
  const values = new Set();
  items.forEach(item => {
    const val = (item[field] || '').trim().toLowerCase();
    if (val) values.add(val);
  });
  return Array.from(values).sort();
}

/**
 * Calculate severity distribution
 * @returns {object} { critical, high, medium, low, info }
 */
function getSeverityDistribution() {
  const dist = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0
  };
  
  allIOCs.forEach(ioc => {
    const sev = (ioc.severity || 'informational').toLowerCase();
    if (dist.hasOwnProperty(sev)) {
      dist[sev]++;
    }
  });
  
  return dist;
}

/**
 * Get threat type distribution
 * @returns {object} { threat_type: count, ... }
 */
function getThreatTypeDistribution() {
  const dist = {};
  
  allIOCs.forEach(ioc => {
    const threatType = (ioc.threat_type || 'unknown').toLowerCase();
    dist[threatType] = (dist[threatType] || 0) + 1;
  });
  
  return dist;
}

/**
 * Get top N threat names
 * @param {number} limit - Number of top items
 * @returns {array} Top threats with counts
 */
function getTopThreats(limit = 10) {
  const threatMap = {};
  
  allIOCs.forEach(ioc => {
    const threat = ioc.threat_name || 'Unknown';
    threatMap[threat] = (threatMap[threat] || 0) + 1;
  });
  
  return Object.entries(threatMap)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/**
 * Get IOCs by date range
 * @param {string} startDate - Start date (YYYY-MM-DD)
 * @param {string} endDate - End date (YYYY-MM-DD)
 * @returns {array} IOCs in range
 */
function getIOCsByDateRange(startDate, endDate) {
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  return allIOCs.filter(ioc => {
    if (!ioc.first_seen) return false;
    const date = new Date(ioc.first_seen.split(' ')[0]);
    return date >= start && date <= end;
  });
}

// Export stats function for feeds.html
function getStats() {
  return {
    total: allIOCs.length,
    byType: getUniqueValues(allIOCs, 'ioc_type'),
    bySeverity: getSeverityDistribution(),
    byThreatType: getThreatTypeDistribution(),
    topThreats: getTopThreats(),
    uniqueThreatNames: getUniqueValues(allIOCs, 'threat_name'),
    allIOCs
  };
}
