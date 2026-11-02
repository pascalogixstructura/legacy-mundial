'use strict';

const $ = (selector) => document.querySelector(selector);
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const current = { file: null, hash: null, verdict: 'NOT_RUN', matches: [], references: [] };

const el = {
  dropzone: $('#dropzone'), fileInput: $('#fileInput'), hashOut: $('#hashOut'),
  hashStatus: $('#hashStatus'), copyHash: $('#copyHash'), fileDetails: $('#fileDetails'),
  fileName: $('#fileName'), fileSize: $('#fileSize'), fileModified: $('#fileModified'),
  primaryHash: $('#primaryHash'), secondaryHash: $('#secondaryHash'), tertiaryHash: $('#tertiaryHash'),
  compareBtn: $('#compareBtn'), resultPanel: $('#resultPanel'), resultSymbol: $('#resultSymbol'),
  verdictText: $('#verdictText'), verdictDetail: $('#verdictDetail'),
  saveTxt: $('#saveTxt'), saveJson: $('#saveJson'), saveBadge: $('#saveBadge'),
  badgeCanvas: $('#badgeCanvas'), aboutBtn: $('#aboutBtn'), aboutDialog: $('#aboutDialog'),
  closeAbout: $('#closeAbout')
};

function formatBytes(bytes) {
  if (bytes === 0) return '0 bytes';
  const units = ['bytes', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / Math.pow(1024, index)).toFixed(index ? 2 : 0) + ' ' + units[index];
}

function setHashStatus(message, state = '') {
  el.hashStatus.textContent = message;
  el.hashStatus.dataset.state = state;
}

function setResult(state, title, detail, symbol) {
  el.resultPanel.dataset.state = state;
  el.resultSymbol.textContent = symbol;
  el.verdictText.textContent = title;
  el.verdictDetail.textContent = detail;
}

function setExportEnabled(enabled) {
  [el.copyHash, el.compareBtn, el.saveTxt, el.saveJson, el.saveBadge].forEach(button => {
    button.disabled = !enabled;
  });
}

async function handleFile(file) {
  if (!file) return;
  current.file = null;
  current.hash = null;
  current.verdict = 'NOT_RUN';
  current.matches = [];
  current.references = [];
  setExportEnabled(false);
  el.hashOut.textContent = 'Calculating fingerprint…';
  setHashStatus('Reading file locally. Do not close this tab.', '');

  if (file.size > MAX_FILE_BYTES) {
    el.hashOut.textContent = 'File exceeds the 100 MB limit.';
    setHashStatus('This file is too large for the current browser-based version.', 'error');
    el.fileInput.value = '';
    return;
  }
  if (!globalThis.crypto?.subtle || !globalThis.isSecureContext) {
    el.hashOut.textContent = 'Secure browser cryptography is unavailable.';
    setHashStatus('Open this tool over HTTPS or localhost in a supported browser.', 'error');
    return;
  }

  try {
    const bytes = await file.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    const hex = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    current.file = file;
    current.hash = hex;
    current.verdict = 'NOT_RUN';
    el.hashOut.textContent = hex;
    el.fileDetails.hidden = false;
    el.fileName.textContent = file.name;
    el.fileSize.textContent = formatBytes(file.size);
    el.fileModified.textContent = file.lastModified ? new Date(file.lastModified).toLocaleString() : 'Not provided';
    setHashStatus('Fingerprint computed successfully in this browser.', 'success');
    setResult('idle', 'Ready to compare', 'Enter a trusted reference hash to check byte-for-byte identity.', 'i');
    setExportEnabled(true);
  } catch (error) {
    el.hashOut.textContent = 'Fingerprint could not be calculated.';
    setHashStatus('Browser hashing failed: ' + error.message, 'error');
    setExportEnabled(false);
  }
}

function normalizeHash(value, label) {
  const hash = value.trim();
  if (!hash) return null;
  if (!/^[a-fA-F0-9]{64}$/.test(hash)) {
    throw new Error(label + ' must contain exactly 64 hexadecimal characters (SHA-256).');
  }
  return hash.toLowerCase();
}

function compareHashes() {
  if (!current.hash) return;
  try {
    const candidates = [
      ['Reference 1', el.primaryHash.value],
      ['Reference 2', el.secondaryHash.value],
      ['Reference 3', el.tertiaryHash.value]
    ];
    const references = candidates.map(([label, value]) => ({ label, hash: normalizeHash(value, label) })).filter(item => item.hash);
    if (!references.length) {
      current.verdict = 'UNKNOWN';
      current.matches = [];
      current.references = [];
      setResult('invalid', 'Reference required', 'Enter at least one trusted 64-character SHA-256 reference.', '!');
      return;
    }
    const matches = references.filter(reference => reference.hash === current.hash).map(reference => reference.label);
    current.references = references.map(({ label, hash }) => ({ label, hash }));
    current.matches = matches;
    if (matches.length) {
      current.verdict = 'MATCH';
      setResult('match', 'MATCH', 'The file digest matches: ' + matches.join(', ') + '. This establishes digest equality with the supplied reference only.', '✓');
    } else {
      current.verdict = 'DIFFERENT';
      setResult('different', 'NO MATCH', 'The computed digest does not match any supplied reference. Check the file and reference source.', '×');
    }
  } catch (error) {
    current.verdict = 'INVALID_REFERENCE';
    current.matches = [];
    current.references = [];
    setResult('invalid', 'Invalid reference hash', error.message, '!');
  }
}

function receipt() {
  if (!current.file || !current.hash) throw new Error('Select and hash a file before exporting a receipt.');
  return {
    schema: 'legacy-mundial-receipt/2.0',
    tool: 'Legacy Mundial — LegacyKey',
    operation: 'local-file-sha256',
    file: { name: current.file.name, size_bytes: current.file.size, last_modified_device_time: current.file.lastModified ? new Date(current.file.lastModified).toISOString() : null },
    digest: { algorithm: 'SHA-256', encoding: 'lowercase-hex', value: current.hash },
    comparison: { verdict: current.verdict, matching_references: current.matches, references: current.references },
    receipt_generated_at_device_time: new Date().toISOString(),
    processing: 'The selected file was read locally by the browser; this tool does not upload file bytes.',
    limitations: [
      'A digest match indicates equality of file bytes against the supplied reference.',
      'A digest alone does not establish authorship, ownership, creation date, originality, legal validity, or trusted timestamp.',
      'The receipt generation time is the device clock and is not a trusted timestamp.'
    ],
    attribution: 'Maynard Rafael Pascasio'
  };
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function baseFilename() {
  const name = current.file?.name || 'file';
  return name.replace(/[\\/:*?"<>|]+/g, '_');
}

function exportText() {
  const data = receipt();
  const lines = [
    'LEGACY MUNDIAL — FILE INTEGRITY RECEIPT',
    '=======================================',
    'FILE: ' + data.file.name,
    'SIZE BYTES: ' + data.file.size_bytes,
    'ALGORITHM: ' + data.digest.algorithm,
    'SHA-256: ' + data.digest.value,
    'VERDICT: ' + data.comparison.verdict,
    'MATCHING REFERENCES: ' + (data.comparison.matching_references.join(', ') || 'None / not compared'),
    'RECEIPT DEVICE TIME: ' + data.receipt_generated_at_device_time,
    '',
    'LIMITATION: A digest match establishes equality with the supplied reference only.',
    'It does not establish authorship, ownership, creation date, originality or legal validity.',
    'The receipt time is generated by the device and is not a trusted timestamp.',
    '',
    'ATTRIBUTION: ' + data.attribution
  ];
  downloadBlob(baseFilename() + '.integrity.txt', new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' }));
}

function exportJson() {
  const data = receipt();
  downloadBlob(baseFilename() + '.integrity.json', new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
}

function exportBadge() {
  const data = receipt();
  const canvas = el.badgeCanvas;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.fillStyle = '#f7f3e9'; ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = '#bd9143'; ctx.lineWidth = 4; ctx.strokeRect(28, 28, w - 56, h - 56);
  ctx.fillStyle = '#10243d'; ctx.font = '600 48px Georgia'; ctx.fillText('LEGACY MUNDIAL', 72, 112);
  ctx.fillStyle = '#bd9143'; ctx.font = '20px Arial'; ctx.fillText('FILE INTEGRITY RECEIPT · SHA-256', 74, 152);
  ctx.strokeStyle = '#d9d2c3'; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(72, 185); ctx.lineTo(w - 72, 185); ctx.stroke();
  ctx.fillStyle = '#17283d'; ctx.font = 'bold 25px Arial'; ctx.fillText('FILE', 74, 242);
  ctx.font = '24px Arial'; ctx.fillText(data.file.name.slice(0, 65), 74, 282);
  ctx.font = 'bold 25px Arial'; ctx.fillText('SHA-256', 74, 355);
  ctx.font = '21px monospace'; ctx.fillText(data.digest.value.slice(0, 32), 74, 397);
  ctx.fillText(data.digest.value.slice(32), 74, 430);
  const verdict = data.comparison.verdict === 'MATCH' ? 'MATCH' : data.comparison.verdict === 'DIFFERENT' ? 'NO MATCH' : 'NOT COMPARED';
  ctx.fillStyle = data.comparison.verdict === 'MATCH' ? '#17633f' : '#596779';
  ctx.font = 'bold 42px Georgia'; ctx.fillText(verdict, 74, 515);
  ctx.fillStyle = '#667487'; ctx.font = '18px Arial';
  ctx.fillText('A digest match is not proof of authorship or date.', 74, 575);
  ctx.fillText('Receipt time: ' + data.receipt_generated_at_device_time, 74, 615);
  ctx.fillText('Maynard Rafael Pascasio · LegacyKey', 74, 655);
  canvas.toBlob(blob => { if (blob) downloadBlob(baseFilename() + '.integrity.png', blob); }, 'image/png');
}

['dragenter', 'dragover'].forEach(type => el.dropzone.addEventListener(type, event => {
  event.preventDefault();
  el.dropzone.classList.add('dragover');
}));
['dragleave', 'drop'].forEach(type => el.dropzone.addEventListener(type, event => {
  event.preventDefault();
  el.dropzone.classList.remove('dragover');
}));
el.dropzone.addEventListener('drop', event => {
  const file = event.dataTransfer?.files?.[0];
  if (file) handleFile(file);
});
el.fileInput.addEventListener('change', event => handleFile(event.target.files?.[0]));
el.compareBtn.addEventListener('click', compareHashes);
el.copyHash.addEventListener('click', async () => {
  if (!current.hash) return;
  try {
    await navigator.clipboard.writeText(current.hash);
    setHashStatus('Fingerprint copied to clipboard.', 'success');
  } catch {
    setHashStatus('Clipboard access was blocked. Select and copy the fingerprint manually.', 'error');
  }
});
el.saveTxt.addEventListener('click', exportText);
el.saveJson.addEventListener('click', exportJson);
el.saveBadge.addEventListener('click', exportBadge);
el.aboutBtn.addEventListener('click', () => el.aboutDialog.showModal());
el.closeAbout.addEventListener('click', () => el.aboutDialog.close());
el.aboutDialog.addEventListener('click', event => {
  if (event.target === el.aboutDialog) el.aboutDialog.close();
});
