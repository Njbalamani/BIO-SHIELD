(function () {
  'use strict';

  var doc = document;
  var BioShield = window.BioShield || (window.BioShield = {});

  function onReady(callback) {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', callback, { once: true });
    } else {
      callback();
    }
  }

  function getCookie(name) {
    var parts = doc.cookie.split(';');
    for (var index = 0; index < parts.length; index += 1) {
      var part = parts[index].trim();
      if (part.indexOf(name + '=') === 0) {
        return decodeURIComponent(part.slice(name.length + 1));
      }
    }
    return '';
  }

  function csrfToken() {
    var meta = doc.querySelector('meta[name="csrf-token"]');
    return (meta && meta.getAttribute('content')) || getCookie('csrftoken') || '';
  }

  function apiFetch(url, options) {
    var config = Object.assign({}, options || {});
    var headers = Object.assign({}, config.headers || {});
    headers['X-CSRFToken'] = csrfToken();
    headers['X-Requested-With'] = 'XMLHttpRequest';
    if (config.body && !(config.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    config.headers = headers;
    config.credentials = config.credentials || 'same-origin';
    return fetch(url, config);
  }

  BioShield.getCookie = getCookie;
  BioShield.csrfToken = csrfToken;
  BioShield.apiFetch = apiFetch;

  function initSidebar() {
    var toggle = doc.querySelector('[data-sidebar-toggle]');
    var backdrop = doc.querySelector('[data-close-sidebar]');
    var sidebar = doc.getElementById('sidebar');
    if (!toggle || !sidebar) return;

    function setOpen(open) {
      doc.body.classList.toggle('sidebar-open', open);
      if (backdrop) backdrop.hidden = !open;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    toggle.addEventListener('click', function () {
      if (window.innerWidth <= 992) {
        setOpen(!doc.body.classList.contains('sidebar-open'));
      } else {
        var collapsed = doc.body.classList.toggle('sidebar-collapsed');
        try { localStorage.setItem('bioshield-sidebar-collapsed', collapsed ? '1' : '0'); } catch (error) { void error; }
      }
    });

    if (backdrop) backdrop.addEventListener('click', function () { setOpen(false); });

    Array.prototype.forEach.call(sidebar.querySelectorAll('a[href]'), function (link) {
      link.addEventListener('click', function () {
        if (window.innerWidth <= 992) setOpen(false);
      });
    });

    doc.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') setOpen(false);
    });

    try {
      if (localStorage.getItem('bioshield-sidebar-collapsed') === '1' && window.innerWidth > 992) {
        doc.body.classList.add('sidebar-collapsed');
      }
    } catch (error) { void error; }

    window.addEventListener('resize', function () {
      if (window.innerWidth > 992) setOpen(false);
    });
  }

  function initOverlays() {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-overlay-open]'), function (trigger) {
      trigger.addEventListener('click', function (event) {
        event.preventDefault();
        var target = doc.getElementById(trigger.getAttribute('data-overlay-target') || trigger.getAttribute('data-target') || '');
        if (target) target.hidden = false;
      });
    });
    Array.prototype.forEach.call(doc.querySelectorAll('[data-overlay-close]'), function (trigger) {
      trigger.addEventListener('click', function () {
        var overlay = trigger.closest('[data-overlay]') || doc.getElementById(trigger.getAttribute('data-overlay-target') || '');
        if (overlay) overlay.hidden = true;
      });
    });
    doc.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        Array.prototype.forEach.call(doc.querySelectorAll('[data-overlay]'), function (overlay) { overlay.hidden = true; });
      }
    });
  }

  function toast(message, type) {
    var stack = doc.getElementById('toast-stack');
    if (!stack) return;
    var node = doc.createElement('div');
    node.className = 'toast' + (type ? ' toast--' + type : '');
    node.setAttribute('role', 'status');
    var mark = doc.createElement('span');
    mark.className = 'message__mark';
    mark.setAttribute('aria-hidden', 'true');
    mark.textContent = '✦';
    var text = doc.createElement('span');
    text.textContent = String(message);
    var close = doc.createElement('button');
    close.type = 'button';
    close.className = 'message__close';
    close.setAttribute('aria-label', 'Dismiss notification');
    close.textContent = '×';
    close.addEventListener('click', function () { node.remove(); });
    node.appendChild(mark);
    node.appendChild(text);
    node.appendChild(close);
    stack.appendChild(node);
    window.setTimeout(function () { node.remove(); }, 6000);
  }
  BioShield.toast = toast;

  function initMessages() {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-dismiss-message]'), function (button) {
      button.addEventListener('click', function () {
        var message = button.closest('.message');
        if (message) message.remove();
      });
    });
    Array.prototype.forEach.call(doc.querySelectorAll('[data-toast]'), function (message) {
      window.setTimeout(function () { message.remove(); }, 12000);
    });
  }

  function normalizePath(value) {
    if (!value || value === '/') return '/';
    return value.replace(/\/+$/, '');
  }

  function initActiveNav() {
    var current = normalizePath(window.location.pathname);
    Array.prototype.forEach.call(doc.querySelectorAll('[data-nav]'), function (link) {
      var href = normalizePath(link.pathname || link.getAttribute('href') || '');
      var active = href === current || (href !== '/' && current.indexOf(href + '/') === 0);
      if (active) {
        link.classList.add('is-active');
        link.setAttribute('aria-current', 'page');
      }
    });
  }

  function initTableFilters() {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-table-filter]'), function (input) {
      var table = doc.querySelector(input.getAttribute('data-table-filter'));
      if (!table) return;
      input.addEventListener('input', function () {
        var query = input.value.trim().toLowerCase();
        Array.prototype.forEach.call(table.querySelectorAll('[data-search-row]'), function (row) {
          row.hidden = query !== '' && row.getAttribute('data-search-row').toLowerCase().indexOf(query) === -1;
        });
      });
    });

    Array.prototype.forEach.call(doc.querySelectorAll('[data-severity-filter]'), function (chip) {
      chip.addEventListener('click', function () {
        var group = chip.parentElement;
        var table = doc.querySelector('#findings-table') || chip.closest('.view-head') && doc.querySelector('table');
        if (!table) return;
        Array.prototype.forEach.call(group.querySelectorAll('[data-severity-filter]'), function (item) {
          item.classList.toggle('chip--active', item === chip);
        });
        var selected = chip.getAttribute('data-severity-filter');
        Array.prototype.forEach.call(table.querySelectorAll('tbody tr[data-severity]'), function (row) {
          row.hidden = selected !== 'all' && row.getAttribute('data-severity') !== selected;
        });
      });
    });
  }

  function initForms() {
    Array.prototype.forEach.call(doc.querySelectorAll('form[data-enhance]'), function (form) {
      var buttons = form.querySelectorAll('button[type="submit"]');
      form.addEventListener('submit', function (event) {
        var confirmMessage = form.getAttribute('data-confirm');
        if (confirmMessage && !window.confirm(confirmMessage)) {
          event.preventDefault();
          return;
        }
        Array.prototype.forEach.call(buttons, function (button) {
          var label = button.getAttribute('data-submit-label');
          if (label && !button.dataset.originalLabel) button.dataset.originalLabel = button.textContent;
          if (label) button.textContent = label;
          button.disabled = true;
          button.classList.add('is-loading');
        });
        window.setTimeout(function () {
          Array.prototype.forEach.call(buttons, function (button) {
            button.disabled = false;
            button.classList.remove('is-loading');
            if (button.dataset.originalLabel) button.textContent = button.dataset.originalLabel;
          });
        }, 10000);
      });
      Array.prototype.forEach.call(form.querySelectorAll('input[maxlength], textarea[maxlength]'), function (field) {
        field.addEventListener('input', function () {
          field.setAttribute('aria-valuenow', String(field.value.length));
        });
      });
    });
  }

  function initFileInputs() {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-file-input]'), function (input) {
      function update() {
        var label = doc.querySelector('[data-file-name]');
        if (!label) return;
        var files = input.files || [];
        label.textContent = files.length ? files[0].name : 'No file selected';
      }
      input.addEventListener('change', update);
      Array.prototype.forEach.call(doc.querySelectorAll('[data-dropzone]'), function (zone) {
        zone.addEventListener('dragover', function (event) {
          event.preventDefault();
          zone.classList.add('is-dragging');
        });
        zone.addEventListener('dragleave', function () { zone.classList.remove('is-dragging'); });
        zone.addEventListener('drop', function (event) {
          event.preventDefault();
          zone.classList.remove('is-dragging');
          if (event.dataTransfer && event.dataTransfer.files.length) {
            input.files = event.dataTransfer.files;
            update();
          }
        });
      });
    });
  }

  function initConfidenceBadges() {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-confidence]'), function (badge) {
      var value = parseFloat(badge.getAttribute('data-confidence'));
      if (!isFinite(value)) return;
      var normalized = value > 1 ? value / 100 : value;
      var level = normalized >= 0.85 ? 'high' : normalized >= 0.6 ? 'medium' : 'low';
      badge.classList.add('badge--confidence-' + level);
    });
  }

  onReady(function () {
    initSidebar();
    initOverlays();
    initMessages();
    initActiveNav();
    initTableFilters();
    initForms();
    initFileInputs();
    initConfidenceBadges();
  });
})();
