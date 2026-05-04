// ── Severity / search filter ──────────────────────────────────────────────
document.querySelectorAll('.fbtn').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.fbtn').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  _applyFindingFilter();
}));

const searchBox = document.getElementById('finding-search');
if (searchBox) searchBox.addEventListener('input', _applyFindingFilter);

function _applyFindingFilter() {
  const f = document.querySelector('.fbtn.active')?.dataset.f || 'all';
  const q = (searchBox?.value || '').toLowerCase();
  document.querySelectorAll('#tbl-findings .fr').forEach(row => {
    const sevOk = f === 'all' || row.dataset.sev === f;
    const qOk   = !q || row.textContent.toLowerCase().includes(q);
    row.style.display = (sevOk && qOk) ? '' : 'none';
  });
}

// ── Tabs ──────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => {
  const panel = document.getElementById(b.dataset.tab);
  if (!panel) return;
  const section = panel.closest('.section');
  section.querySelectorAll('.tab-btn').forEach(x => x.classList.remove('active'));
  section.querySelectorAll('.tab-panel').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  panel.classList.add('active');
}));

// ── Copy chart as PNG ─────────────────────────────────────────────────────
// Inline SVGs cannot be right-click copied by browsers — this converts them
// to a PNG on a canvas and writes it to the clipboard.
function copyChartAsPng(btn) {
  const card = btn.closest('.chart-card');
  const svg  = card.querySelector('svg');
  if (!svg) return;

  // Clone SVG, set explicit background matching the card color
  const clone = svg.cloneNode(true);
  const bgColor = '#1a2035';
  clone.style.background = bgColor;
  // Ensure width/height are set as attributes so Canvas can size properly
  const w = svg.viewBox.baseVal.width  || svg.getBoundingClientRect().width  || 400;
  const h = svg.viewBox.baseVal.height || svg.getBoundingClientRect().height || 280;
  clone.setAttribute('width',  w);
  clone.setAttribute('height', h);

  const svgStr  = new XMLSerializer().serializeToString(clone);
  const svgBlob = new Blob([svgStr], {type: 'image/svg+xml;charset=utf-8'});
  const url     = URL.createObjectURL(svgBlob);
  const scale   = 2; // retina-quality output

  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width  = w * scale;
    canvas.height = h * scale;
    const ctx = canvas.getContext('2d');
    ctx.scale(scale, scale);
    ctx.fillStyle = bgColor;
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(img, 0, 0, w, h);
    URL.revokeObjectURL(url);

    canvas.toBlob(blob => {
      navigator.clipboard.write([new ClipboardItem({'image/png': blob})])
        .then(() => {
          btn.textContent = '✓ Copied!';
          btn.style.color = '#2ecc71';
          setTimeout(() => { btn.textContent = '📋 Copy as PNG'; btn.style.color = ''; }, 2000);
        })
        .catch(() => {
          // Fallback: open PNG in new tab so user can save manually
          const dataUrl = canvas.toDataURL('image/png');
          const a = document.createElement('a');
          a.href = dataUrl;
          a.download = 'chart.png';
          a.click();
        });
    }, 'image/png');
  };
  img.onerror = () => URL.revokeObjectURL(url);
  img.src = url;
}

// ── Collapsible remediation steps in findings ────────────────────────────
document.querySelectorAll('.rem-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const block = btn.nextElementSibling;
    const open  = block.style.display !== 'none';
    block.style.display = open ? 'none' : '';
    btn.textContent = open ? '▶ Mostrar pasos de remediación' : '▼ Ocultar pasos de remediación';
  });
});

// ── Sortable table columns ────────────────────────────────────────────────
document.querySelectorAll('.sortable th[data-col]').forEach(th => {
  th.style.cursor = 'pointer';
  th.title = 'Click to sort';
  th.addEventListener('click', () => {
    const table = th.closest('table');
    const tbody = table.querySelector('tbody');
    const col   = parseInt(th.dataset.col);
    const asc   = th.dataset.asc !== '1';
    th.dataset.asc = asc ? '1' : '0';
    table.querySelectorAll('th[data-col]').forEach(h => h.removeAttribute('data-asc'));
    th.dataset.asc = asc ? '1' : '0';
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
      const av = a.cells[col]?.textContent.trim() || '';
      const bv = b.cells[col]?.textContent.trim() || '';
      const n  = parseFloat(av) - parseFloat(bv);
      const cmp = isNaN(n) ? av.localeCompare(bv) : n;
      return asc ? cmp : -cmp;
    });
    rows.forEach(r => tbody.appendChild(r));
    th.textContent = th.textContent.replace(/ [▲▼]$/, '') + (asc ? ' ▲' : ' ▼');
  });
});
