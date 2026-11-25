(function () {
  'use strict';

  var doc = document;
  var BioShield = window.BioShield || (window.BioShield = {});
  var allowedKinds = ['person', 'id', 'date', 'org', 'phi'];

  function parseMasks(raw) {
    if (!raw) return [];
    try {
      var parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      return [];
    }
  }

  function safeKind(kind) {
    var value = String(kind || 'entity').toLowerCase();
    var matched = allowedKinds.filter(function (item) { return value.indexOf(item) !== -1; });
    return matched.length ? matched[0] : 'phi';
  }

  function appendText(target, value) {
    if (!value) return;
    target.appendChild(doc.createTextNode(value));
  }

  function renderElement(element) {
    var text = element.getAttribute('data-text') || element.textContent || '';
    var masks = parseMasks(element.getAttribute('data-masks'));
    element.textContent = '';

    if (!text.trim()) {
      var empty = doc.createElement('span');
      empty.className = 'muted';
      empty.textContent = 'No excerpt available for this synthetic document.';
      element.appendChild(empty);
      return;
    }

    var prepared = masks.map(function (mask) {
      if (!mask || typeof mask !== 'object') return null;
      var start = Number(mask.start !== undefined ? mask.start : mask.begin);
      var end = Number(mask.end !== undefined ? mask.end : mask.stop);
      if (!isFinite(start) || !isFinite(end)) return null;
      start = Math.max(0, Math.min(start, text.length));
      end = Math.max(start, Math.min(end, text.length));
      if (end === start) return null;
      return {
        start: start,
        end: end,
        kind: safeKind(mask.kind || mask.label || mask.entity_type || mask.type),
        replacement: String(mask.masked_text || mask.masked_value || mask.replacement || '[REDACTED]'),
        confidence: mask.confidence
      };
    }).filter(function (mask) { return mask !== null; });

    prepared.sort(function (a, b) { return a.start - b.start || a.end - b.end; });

    var cursor = 0;
    prepared.forEach(function (mask) {
      if (mask.start < cursor) return;
      appendText(element, text.slice(cursor, mask.start));
      var span = doc.createElement('span');
      span.className = 'masked masked--' + mask.kind;
      span.setAttribute('data-entity', mask.kind);
      span.setAttribute('title', 'Masked ' + mask.kind + ' entity');
      if (mask.confidence !== undefined) span.setAttribute('data-confidence', String(mask.confidence));
      span.textContent = mask.replacement;
      element.appendChild(span);
      cursor = mask.end;
    });
    appendText(element, text.slice(cursor));
  }

  function renderAll() {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-highlight-excerpt]'), renderElement);
  }

  BioShield.renderHighlights = renderAll;

  if (doc.readyState === 'loading') {
    doc.addEventListener('DOMContentLoaded', renderAll, { once: true });
  } else {
    renderAll();
  }
})();
