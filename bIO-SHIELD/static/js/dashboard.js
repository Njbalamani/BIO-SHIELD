(function () {
  'use strict';

  var doc = document;
  var BioShield = window.BioShield || (window.BioShield = {});

  var palette = {
    gold: '#dfbe6d',
    goldSoft: 'rgba(223, 190, 109, 0.24)',
    mint: '#62d8b4',
    mintSoft: 'rgba(98, 216, 180, 0.22)',
    silver: '#bdc9da',
    silverSoft: 'rgba(189, 201, 218, 0.18)',
    violet: '#a99cf5',
    rose: '#ff8493',
    blue: '#78b2ec'
  };

  var chartPalette = [palette.gold, palette.mint, palette.violet, palette.blue, palette.silver, palette.rose];

  function readData() {
    var node = doc.getElementById('dashboard-data');
    if (!node) return {};
    try {
      var parsed = JSON.parse(node.textContent || '{}');
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (error) {
      return {};
    }
  }

  function firstValue(source, keys) {
    for (var index = 0; index < keys.length; index += 1) {
      if (source && source[keys[index]] !== undefined && source[keys[index]] !== null) {
        return source[keys[index]];
      }
    }
    return null;
  }

  function labelOf(item) {
    if (item === null || item === undefined) return 'unknown';
    if (typeof item !== 'object') return String(item);
    return String(firstValue(item, ['label', 'name', 'category', 'type', 'key', 'risk_level', 'severity']) || 'unknown');
  }

  function valueOf(item) {
    if (typeof item === 'number') return item;
    if (typeof item === 'string') {
      var parsed = Number(item);
      return isFinite(parsed) ? parsed : 0;
    }
    if (item && typeof item === 'object') {
      var raw = firstValue(item, ['value', 'count', 'total', 'amount']);
      var number = Number(raw);
      return isFinite(number) ? number : 0;
    }
    return 0;
  }

  function normalize(source) {
    if (!source) return [];
    if (Array.isArray(source)) {
      return source.map(function (item) {
        return { label: labelOf(item), value: valueOf(item) };
      });
    }
    if (typeof source === 'object') {
      return Object.keys(source).map(function (key) {
        return { label: key, value: valueOf(source[key]) };
      });
    }
    return [];
  }

  function hasData(rows) {
    return rows.length > 0 && rows.some(function (row) { return row.value > 0; });
  }

  function fallback(canvas, message) {
    if (!canvas || !canvas.parentElement) return;
    canvas.hidden = true;
    var existing = canvas.parentElement.querySelector('.chart-fallback');
    if (existing) existing.remove();
    var note = doc.createElement('div');
    note.className = 'chart-fallback';
    note.textContent = message;
    canvas.parentElement.appendChild(note);
  }

  function chartAvailable() {
    return typeof window.Chart === 'function';
  }

  function applyDefaults() {
    if (!chartAvailable()) return;
    window.Chart.defaults.color = palette.silver;
    window.Chart.defaults.font.family = 'Inter, "Segoe UI", system-ui, sans-serif';
    window.Chart.defaults.font.size = 11;
    window.Chart.defaults.animation.duration = 650;
  }

  function baseOptions() {
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, boxHeight: 10, padding: 14 } },
        tooltip: { backgroundColor: 'rgba(7, 11, 22, 0.94)', borderColor: 'rgba(223, 190, 109, 0.3)', borderWidth: 1 }
      }
    };
  }

  function barOptions() {
    var options = baseOptions();
    options.plugins.legend = { display: false };
    options.scales = {
      x: { grid: { color: 'rgba(196, 211, 234, 0.08)' }, ticks: { color: palette.silver } },
      y: { beginAtZero: true, grid: { color: 'rgba(196, 211, 234, 0.08)' }, ticks: { color: palette.silver, precision: 0 } }
    };
    return options;
  }

  function doughnutOptions() {
    var options = baseOptions();
    options.cutout = '62%';
    return options;
  }

  function renderChart(canvasId, rows, type, options, colors, emptyMessage) {
    var canvas = doc.getElementById(canvasId);
    if (!canvas) return null;
    if (!hasData(rows)) {
      fallback(canvas, emptyMessage);
      return null;
    }
    if (!chartAvailable()) {
      fallback(canvas, 'Chart.js is unavailable. Figures remain available in the data table.');
      return null;
    }
    try {
      var ctx = canvas.getContext('2d');
      if (!ctx) return null;
      canvas.hidden = false;
      return new window.Chart(ctx, {
        type: type,
        data: {
          labels: rows.map(function (row) { return row.label; }),
          datasets: [{
            data: rows.map(function (row) { return row.value; }),
            backgroundColor: colors,
            borderColor: 'rgba(7, 11, 22, 0.65)',
            borderWidth: type === 'bar' ? 0 : 2,
            borderRadius: type === 'bar' ? 8 : 0,
            hoverOffset: type === 'doughnut' ? 8 : 0
          }]
        },
        options: options
      });
    } catch (error) {
      fallback(canvas, 'Chart could not be rendered.');
      return null;
    }
  }

  function severityColors(rows) {
    return rows.map(function (row) {
      var name = row.label.toLowerCase();
      if (name.indexOf('high') !== -1 || name.indexOf('critical') !== -1) return palette.rose;
      if (name.indexOf('medium') !== -1 || name.indexOf('moderate') !== -1) return palette.gold;
      if (name.indexOf('low') !== -1) return palette.mint;
      return palette.violet;
    });
  }

  function riskColors(rows) {
    return rows.map(function (row) {
      var name = row.label.toLowerCase();
      if (name.indexOf('high') !== -1 || name.indexOf('critical') !== -1) return palette.rose;
      if (name.indexOf('medium') !== -1 || name.indexOf('moderate') !== -1) return palette.gold;
      return palette.mint;
    });
  }

  function textCell(row, value) {
    var cell = doc.createElement('td');
    cell.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
    row.appendChild(cell);
  }

  function renderAccessEvents(events) {
    var body = doc.getElementById('access-events-body');
    if (!body) return;
    body.textContent = '';
    if (!Array.isArray(events) || events.length === 0) {
      var emptyRow = doc.createElement('tr');
      var emptyCell = doc.createElement('td');
      emptyCell.colSpan = 5;
      emptyCell.className = 'table-empty';
      emptyCell.textContent = 'No access events available yet.';
      emptyRow.appendChild(emptyCell);
      body.appendChild(emptyRow);
      return;
    }
    events.slice(0, 12).forEach(function (event) {
      var row = doc.createElement('tr');
      textCell(row, firstValue(event, ['timestamp', 'created_at', 'time', 'at']));
      textCell(row, firstValue(event, ['actor', 'actor_name', 'actor_email', 'user']));
      textCell(row, firstValue(event, ['event_type', 'action', 'event', 'type']));
      textCell(row, firstValue(event, ['document', 'document_title', 'resource', 'target']));
      textCell(row, firstValue(event, ['outcome', 'result', 'status']));
      body.appendChild(row);
    });
  }

  function render() {
    var data = readData();
    applyDefaults();

    var categories = normalize(firstValue(data, ['findings_by_category', 'categories', 'findingsByCategory']));
    var severity = normalize(firstValue(data, ['severity_distribution', 'severity', 'severityCounts']));
    var risk = normalize(firstValue(data, ['risk_levels', 'riskLevels', 'risk_distribution']));
    var events = firstValue(data, ['access_events', 'accessEvents', 'recent_access', 'events']);

    renderChart('findings-category-chart', categories, 'bar', barOptions(), palette.gold, 'No category data available yet.');
    renderChart('severity-chart', severity, 'doughnut', doughnutOptions(), severityColors(severity), 'No severity data available yet.');
    renderChart('risk-level-chart', risk, 'bar', barOptions(), riskColors(risk), 'No assessment data available yet.');
    renderAccessEvents(events);
  }

  BioShield.renderDashboard = render;

  if (doc.readyState === 'loading') {
    doc.addEventListener('DOMContentLoaded', render, { once: true });
  } else {
    render();
  }
})();
