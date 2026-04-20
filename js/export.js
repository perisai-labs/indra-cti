// Indra CTI Portal — Export Functions

/**
 * Export IOCs as JSON
 */
async function exportAsJSON() {
  const btn = document.getElementById('btn-json');
  btn.disabled = true;
  btn.textContent = '⏳ Loading...';
  
  try {
    // Load data if not already loaded
    if (allIOCs.length === 0) {
      await initializeStats();
    }
    
    if (allIOCs.length === 0) {
      alert('No IOC data available');
      return;
    }
    
    // Create JSON structure
    const data = {
      metadata: {
        source: 'Indra CTI by Peris.ai',
        url: 'https://perisai-labs.github.io/indra-cti/',
        license: 'CC BY 4.0',
        generated: new Date().toISOString(),
        total_iocs: allIOCs.length
      },
      data: allIOCs
    };
    
    // Export
    const json = JSON.stringify(data, null, 2);
    const timestamp = new Date().toISOString().split('T')[0];
    downloadFile(json, `indra-cti-iocs_${timestamp}.json`, 'application/json');
    
    btn.textContent = '✓ Downloaded!';
    setTimeout(() => {
      btn.textContent = '📄 Export as JSON';
      btn.disabled = false;
    }, 2000);
  } catch (error) {
    console.error('Export error:', error);
    alert('Export failed: ' + error.message);
    btn.textContent = '📄 Export as JSON';
    btn.disabled = false;
  }
}

/**
 * Export IOCs as STIX 2.1 Bundle
 */
async function exportAsSTIX() {
  const btn = document.getElementById('btn-stix');
  btn.disabled = true;
  btn.textContent = '⏳ Loading...';
  
  try {
    // Load data if not already loaded
    if (allIOCs.length === 0) {
      await initializeStats();
    }
    
    if (allIOCs.length === 0) {
      alert('No IOC data available');
      return;
    }
    
    // Convert to STIX 2.1 Indicators
    const objects = allIOCs.map(ioc => {
      const threatName = ioc.threat_name || 'Unknown Threat';
      const pattern = generateSTIXPattern(ioc.ioc_type, ioc.ioc_value);
      
      if (!pattern) return null; // Skip unsupported types
      
      return {
        type: 'indicator',
        id: `indicator--${generateUUID()}`,
        created: ioc.first_seen ? new Date(ioc.first_seen).toISOString() : new Date().toISOString(),
        modified: ioc.last_seen ? new Date(ioc.last_seen).toISOString() : new Date().toISOString(),
        pattern: pattern,
        pattern_type: 'stix',
        labels: ['malicious-activity'],
        name: threatName,
        description: ioc.description || '',
        valid_from: ioc.first_seen ? new Date(ioc.first_seen).toISOString() : new Date().toISOString(),
        kill_chain_phases: ioc.mitre_attack ? [{
          kill_chain_name: 'mitre-attack',
          phase_name: ioc.mitre_attack.toLowerCase().replace(/\./g, '-')
        }] : [],
        external_references: [{
          source_name: 'Indra CTI',
          url: 'https://perisai-labs.github.io/indra-cti/'
        }]
      };
    }).filter(obj => obj !== null);
    
    // Create STIX Bundle
    const bundle = {
      type: 'bundle',
      id: `bundle--${generateUUID()}`,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      objects: [
        // Add identity object
        {
          type: 'identity',
          id: `identity--${generateUUID()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: 'Peris.ai',
          identity_class: 'organization',
          description: 'Indra CTI - Open-Source Threat Intelligence Platform'
        },
        // Add threat report object
        {
          type: 'malware',
          id: `malware--${generateUUID()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: 'Indra CTI Composite Threat',
          labels: ['malware'],
          description: 'Composite threat intelligence from Indra CTI'
        },
        ...objects
      ]
    };
    
    // Export
    const stix = JSON.stringify(bundle, null, 2);
    const timestamp = new Date().toISOString().split('T')[0];
    downloadFile(stix, `indra-cti-stix_${timestamp}.json`, 'application/json');
    
    btn.textContent = '✓ Downloaded!';
    setTimeout(() => {
      btn.textContent = '🔗 Export as STIX 2.1';
      btn.disabled = false;
    }, 2000);
  } catch (error) {
    console.error('STIX export error:', error);
    alert('STIX export failed: ' + error.message);
    btn.textContent = '🔗 Export as STIX 2.1';
    btn.disabled = false;
  }
}

/**
 * Generate STIX pattern from IOC
 * @param {string} type - IOC type
 * @param {string} value - IOC value
 * @returns {string} STIX pattern string
 */
function generateSTIXPattern(type, value) {
  const escapedValue = value.replace(/'/g, "\\'");
  
  const patterns = {
    'hash-md5': `[file:hashes.MD5 = '${escapedValue}']`,
    'hash-sha256': `[file:hashes.SHA-256 = '${escapedValue}']`,
    'hash-sha1': `[file:hashes.SHA-1 = '${escapedValue}']`,
    'hash-ssdeep': `[file:hashes.SSDEEP = '${escapedValue}']`,
    'ip': `[ipv4-addr:value = '${escapedValue}']`,
    'ipv4': `[ipv4-addr:value = '${escapedValue}']`,
    'ipv6': `[ipv6-addr:value = '${escapedValue}']`,
    'domain': `[domain-name:value = '${escapedValue}']`,
    'url': `[url:value = '${escapedValue}']`,
    'email': `[email-addr:value = '${escapedValue}']`,
    'filename': `[file:name = '${escapedValue}']`,
    'registry': `[windows-registry-key:key = '${escapedValue}']`
  };
  
  const typeKey = type.toLowerCase();
  return patterns[typeKey] || null;
}

/**
 * Initialize exports on page load
 */
document.addEventListener('DOMContentLoaded', () => {
  // Pre-load IOC data for quick export
  initializeStats().catch(err => {
    console.warn('Stats initialization warning:', err);
  });
});
