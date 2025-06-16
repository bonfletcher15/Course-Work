let allScans = [];

function showTab(tab) {
  document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => (content.style.display = 'none'));
  document.getElementById(`${tab}-tab`).style.display = 'block';
  document.querySelector(`[onclick="showTab('${tab}')"]`).classList.add('active');
}

async function openHistoryModal() {
  const modal = document.getElementById('history-modal');
  const list = document.getElementById('history-list');
  list.innerHTML = 'Loading...';

  try {
    const response = await fetch('/api/scans');
    if (!response.ok) throw new Error('Failed to fetch scans');
    allScans = await response.json();

    renderScans();

  } catch (error) {
    list.innerHTML = `<li>Error loading scans: ${error.message}</li>`;
  }

  modal.style.display = 'flex';
}

function applyFilters(scans) {
  const type = document.getElementById('filter-type').value;
  const severity = document.getElementById('filter-severity').value;

  return scans.filter(scan => {
    const matchesType = !type || scan.type === type;
    const matchesSeverity = !severity || scan.severity === severity;
    return matchesType && matchesSeverity;
  });
}

function renderScans() {
  const list = document.getElementById('history-list');
  const filtered = applyFilters(allScans);
  list.innerHTML = '';

  if (filtered.length === 0) {
    list.innerHTML = '<li>No scans match the filters.</li>';
    return;
  }

  filtered.forEach(scan => {
    const li = document.createElement('li');
    li.innerHTML = `
      <div>${scan.input_value} - ${scan.severity}</div>
      <div>
        <button class="btn btn-view" onclick="viewScan('${scan.input_value}')">View</button>
        <button class="btn btn-delete" onclick="deleteScan('${scan.input_value}')">Delete</button>
      </div>
    `;
    list.appendChild(li);
  });
}

function viewScan(name) {
  window.location.href = `/view_scan/${encodeURIComponent(name)}`;
}

async function deleteScan(name) {
  if (!confirm('Delete this scan?')) return;

  const res = await fetch(`/api/delete_scan/${encodeURIComponent(name)}`, { method: 'DELETE' });
  if (res.ok) {
    await openHistoryModal();
  } else {
    alert('Failed to delete scan.');
  }
}

async function loadRecentScans() {
  const list = document.getElementById('recent-scans-list');
  list.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/recent_scans');
    const scans = await res.json();
    list.innerHTML = '';
    scans.forEach(scan => {
      const li = document.createElement('li');
      li.innerHTML = `<a href="/view_scan/${encodeURIComponent(scan.input_value)}">${scan.input_value} - ${scan.severity}</a>`;
      list.appendChild(li);
    });
  } catch {
    list.innerHTML = '<li>Error loading scans</li>';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadRecentScans();

  document.getElementById('filter-type').addEventListener('change', renderScans);
  document.getElementById('filter-severity').addEventListener('change', renderScans);
});

document.getElementById('history-modal').addEventListener('click', e => {
  if (e.target.id === 'history-modal' || e.target.classList.contains('close-btn')) {
    e.target.closest('#history-modal').style.display = 'none';
  }
});