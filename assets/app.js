const INTEL = {
  data: null,
  warning: null,
  articles: [],
  geoPoints: [],
  MAP_W: 1000,
  MAP_H: 500,
  LAT_TOP: 83,
  LAT_BOTTOM: -55,

  async init() {
    this.injectStyles();
    try {
      const response = await fetch('data/output.json', { cache: 'no-store' });
      if (!response.ok) throw new Error('data request returned ' + response.status);
      this.data = await response.json();
    } catch (error) {
      this.renderError(error);
      return;
    }
    this.articles = (this.data.events && this.data.events.length)
      ? this.data.events
      : ((this.data.live_data && (this.data.live_data.news_articles || this.data.live_data.news_articles)) || []);
    this.geoPoints = (this.data.live_data && this.data.live_data.geo_points) || [];
    this.warning = this.data.early_warning || null;
    this.renderMode();
    this.renderStatus();
    this.renderEarlyWarning();
    this.renderStats();
    this.renderKevRadar();
    this.renderEpssFrontier();
    this.renderSourceTable();
    this.renderEvents();
    this.renderSourceTags();
    this.renderGeneratedTime();
    this.renderAnalysis();
    this.setupTabs();
    await this.renderTimeline();
  },

  injectStyles() {
    if (document.getElementById('intel-extra-styles')) return;
    const style = document.createElement('style');
    style.id = 'intel-extra-styles';
    style.textContent =
      '.list-item-copy{display:flex;flex-direction:column;gap:.25rem;min-width:0;color:inherit}' +
      '.list-item-copy:hover .list-item-title{color:var(--accent-hover)}' +
      '.chart-gridline{stroke:rgba(243,239,228,0.08);stroke-width:1}' +
      '.timeline-area{fill:rgba(215,180,106,0.12);stroke:none}' +
      '.timeline-line{fill:none;stroke:#d7b46a;stroke-width:1.5}' +
      '.timeline-point{fill:#e7c882}' +
      '.chart-label{fill:#a9a496;font-size:10px;font-family:JetBrains Mono,monospace}' +
      '.map-label{fill:#a9a496;font-size:11px;font-family:JetBrains Mono,monospace}' +
      '.land-path{fill:#12293c;stroke:rgba(243,239,228,0.18);stroke-width:0.5}' +
      '.signal-pulse{fill:rgba(215,180,106,0.15)}' +
      '.signal-point{fill:#d7b46a;stroke:#071522;stroke-width:1}' +
      '.signal-point.high{fill:#ef4444}.signal-point.medium{fill:#f59e0b}.signal-point.low{fill:#10b981}';
    document.head.appendChild(style);
  },

  cleanText(value) {
    if (!value) return '';
    const text = String(value);
    try {
      const bytes = Uint8Array.from(text, c => c.charCodeAt(0));
      const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      return /[ÃÂÐ]/.test(text) ? decoded : text;
    } catch { return text; }
  },

  parseDate(value) {
    if (!value) return null;
    const compact = String(value).match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
    const date = compact
      ? new Date(Date.UTC(+compact[1], +compact[2] - 1, +compact[3], +compact[4], +compact[5], +compact[6]))
      : new Date(value);
    return Number.isFinite(date.getTime()) ? date : null;
  },

  formatDate(value, includeTime = true) {
    const date = this.parseDate(value);
    if (!date) return '\u2014';
    const options = includeTime
      ? { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }
      : { day: 'numeric', month: 'short', timeZone: 'UTC' };
    return new Intl.DateTimeFormat('en-GB', options).format(date);
  },

  uniqueDomains(articles) {
    return new Set(articles.map(a => a.domain).filter(Boolean)).size;
  },

  meanTone(articles) {
    const tones = articles.map(a => Number(a.tone)).filter(Number.isFinite);
    return tones.length ? tones.reduce((s, v) => s + v, 0) / tones.length : 0;
  },

  mode() {
    const mode = (this.data.meta && this.data.meta.mode) || 'unavailable';
    if (!this.articles.length) return 'unavailable';
    return mode === 'live' ? 'live' : mode === 'partial' ? 'partial' : 'degraded';
  },

  renderMode() {
    const el = document.getElementById('data-mode');
    if (!el) return;
    const labels = { live: 'Live \u00b7 6h refresh', partial: 'Retained \u00b7 6h refresh', degraded: 'Degraded \u00b7 6h refresh', unavailable: 'Unavailable' };
    el.textContent = labels[this.mode()] || labels.unavailable;
  },

  renderStatus() {
    const alert = document.querySelector('main .alert');
    if (!alert) return;
    const notes = (this.data.meta && this.data.meta.source_notes) || [];
    const mode = this.mode();
    alert.classList.remove('alert-info', 'alert-warning', 'alert-danger');
    alert.classList.add(mode === 'live' ? 'alert-info' : mode === 'unavailable' ? 'alert-danger' : 'alert-warning');
    const base = alert.dataset.baseText || alert.textContent.trim();
    alert.dataset.baseText = base;
    const health = (this.warning && this.warning.data_health) || {};
    const counts = this.warning
      ? ` ${health.cisa_catalog_count || 0} CISA KEVs, ${health.epss_frontier_count || 0} forward candidates, and ${health.news_events_considered || 0} recent public signals evaluated.`
      : ' No validated warning snapshot is available.';
    const note = notes.length ? ' ' + notes.join(' ') : '';
    alert.replaceChildren();
    const strong = document.createElement('strong');
    strong.textContent = 'Intelligence status: ';
    alert.append(strong, document.createTextNode(base.replace(/^Intelligence status:\s*/i, '').trim() + counts + note));
  },

  renderStats() {
    const grid = document.querySelector('.stat-grid');
    if (!grid) return;
    const warning = this.warning || {};
    const components = new Map((warning.components || []).map(row => [row.id, row]));
    const kev = components.get('kev_addition_pressure') || {};
    const epss = components.get('epss_frontier_momentum') || {};
    const narrative = components.get('exploit_narrative_pressure') || {};
    const stats = [
      { value: `${Number(warning.score || 0).toFixed(1)}`, label: 'Pressure Index', note: warning.level || 'unavailable', cls: Number(warning.score || 0) >= 55 ? 'down' : 'neutral' },
      { value: String(kev.recent_7d_count ?? '\u2014'), label: 'New KEVs · 7d', note: `prior week ${kev.prior_7d_count ?? '\u2014'}`, cls: 'neutral' },
      { value: String(epss.accelerated_7d_count ?? '\u2014'), label: 'EPSS Accelerators', note: 'not yet in KEV', cls: 'neutral' },
      { value: String(narrative.independent_sources ?? this.uniqueDomains(this.articles)), label: 'Distinct News Sources', note: `${narrative.matched_event_count ?? 0} matched signals`, cls: 'neutral' },
    ];
    grid.replaceChildren(...stats.map(s => {
      const card = document.createElement('div');
      card.className = 'stat-card';
      card.innerHTML = `<div class="stat-value">${s.value}</div><div class="stat-label">${s.label}</div><div class="stat-delta ${s.cls}">${s.note}</div>`;
      return card;
    }));
  },

  renderEarlyWarning() {
    const warning = this.warning;
    if (!warning) return;
    const score = document.getElementById('warning-score');
    const level = document.getElementById('warning-level');
    const summary = document.getElementById('warning-summary');
    if (score) score.textContent = Number(warning.score).toFixed(1);
    if (level) { level.textContent = warning.level; level.dataset.level = String(warning.level || '').toLowerCase(); }
    if (summary) summary.textContent = warning.method && warning.method.warning
      ? warning.method.warning
      : 'Global exploitation pressure derived from public, reproducible sources.';
    const confidence = document.getElementById('warning-confidence');
    const horizon = document.getElementById('warning-horizon');
    const concurrence = document.getElementById('warning-concurrence');
    if (confidence) confidence.textContent = `${warning.confidence} · ${Number(warning.confidence_score).toFixed(0)}%`;
    if (horizon) horizon.textContent = warning.horizon;
    if (concurrence) concurrence.textContent = warning.concurrence && warning.concurrence.active
      ? `${warning.concurrence.elevated_components.length} domains · +${warning.concurrence.score_bonus}`
      : 'No bonus';

    const components = document.getElementById('warning-components');
    if (components) components.replaceChildren(...(warning.components || []).map(component => {
      const card = document.createElement('article');
      card.className = 'warning-component';
      const retained = component.retained ? '<em>Retained &lt;72h</em>' : '<em>Current</em>';
      card.innerHTML = `<div><span>${component.label}</span>${retained}</div><strong>${component.available ? Number(component.score).toFixed(1) : '\u2014'}</strong><div class="component-bar"><i style="width:${component.available ? Math.max(1, Number(component.score)) : 0}%"></i></div>`;
      return card;
    }));

    const alerts = document.getElementById('warning-alerts');
    if (alerts) {
      const rows = warning.alerts || [];
      if (!rows.length) {
        const p = document.createElement('p');
        p.textContent = 'No component currently exceeds the WATCH threshold.';
        alerts.replaceChildren(p);
      } else {
        alerts.replaceChildren(...rows.map(row => {
          const item = document.createElement('article');
          item.innerHTML = `<b>${row.level} · ${Number(row.score).toFixed(1)}</b><span>${row.title}</span><p>${row.why}</p>`;
          return item;
        }));
      }
    }

    const health = document.getElementById('warning-health');
    if (health) {
      const values = warning.data_health || {};
      const chips = [
        ['CISA', `${values.cisa_catalog_count || 0} records`],
        ['EPSS', `${values.epss_frontier_count || 0} frontier`],
        ['History', `${values.epss_timeseries_count || 0} series`],
        ['News', `${values.news_events_considered || 0} events`],
        ['Sources', `${values.independent_news_sources || 0} distinct`],
        ['Components', `${values.available_components || 0}/3 available`],
      ];
      health.replaceChildren(...chips.map(([label, value]) => {
        const chip = document.createElement('span');
        chip.innerHTML = `<b>${label}</b>${value}`;
        return chip;
      }));
    }
  },

  renderKevRadar() {
    const target = document.getElementById('kev-radar');
    if (!target) return;
    const component = (this.warning && this.warning.components || []).find(row => row.id === 'kev_addition_pressure');
    const rows = (component && component.evidence) || [];
    if (!rows.length) {
      target.innerHTML = '<p class="chart-empty">No CISA additions in the latest seven-day window.</p>';
      return;
    }
    target.replaceChildren(...rows.map(row => {
      const item = document.createElement('article');
      item.className = 'radar-row';
      const link = document.createElement('a');
      link.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(row.cveID || '')}`;
      link.target = '_blank'; link.rel = 'noreferrer noopener';
      link.innerHTML = `<strong>${row.cveID || 'CVE'}</strong><span>${this.cleanText(row.vendorProject || '')} · ${this.cleanText(row.product || '')}</span><p>${this.cleanText(row.vulnerabilityName || row.shortDescription || '')}</p>`;
      const meta = document.createElement('div');
      meta.className = 'radar-meta';
      meta.textContent = `${row.dateAdded || '\u2014'} · due ${row.dueDate || '\u2014'}${String(row.knownRansomwareCampaignUse).toLowerCase() === 'known' ? ' · ransomware known' : ''}`;
      item.append(link, meta);
      return item;
    }));
  },

  renderEpssFrontier() {
    const body = document.getElementById('epss-rows');
    if (!body) return;
    const component = (this.warning && this.warning.components || []).find(row => row.id === 'epss_frontier_momentum');
    const rows = (component && component.evidence || []).slice(0, 10);
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="3">No validated EPSS frontier.</td></tr>';
      return;
    }
    body.replaceChildren(...rows.map(row => {
      const tr = document.createElement('tr');
      const delta = Number(row.delta_7d || 0);
      tr.innerHTML = `<td><a href="${row.url}" target="_blank" rel="noreferrer noopener">${row.cve}</a></td><td>${(Number(row.epss) * 100).toFixed(1)}%</td><td class="${delta > 0 ? 'delta-up' : ''}">${delta >= 0 ? '+' : ''}${(delta * 100).toFixed(1)}pp</td>`;
      return tr;
    }));
  },

  groupSources(articles) {
    const groups = new Map();
    articles.forEach(article => {
      const source = article.domain || article.source || 'Unknown';
      const current = groups.get(source) || { source, count: 0, tones: [] };
      current.count += 1;
      const tone = Number(article.tone);
      if (Number.isFinite(tone)) current.tones.push(tone);
      groups.set(source, current);
    });
    return [...groups.values()].sort((a, b) => b.count - a.count || a.source.localeCompare(b.source));
  },

  renderSourceTable() {
    const body = document.getElementById('entity-rows');
    if (!body) return;
    const groups = this.groupSources(this.articles).slice(0, 10);
    if (!groups.length) {
      body.innerHTML = '<tr><td colspan="4" class="chart-empty">No source activity in the current snapshot.</td></tr>';
      return;
    }
    const maximum = Math.max(...groups.map(g => g.count));
    body.replaceChildren(...groups.map(group => {
      const mean = group.tones.length ? group.tones.reduce((a, b) => a + b, 0) / group.tones.length : 0;
      const toneClass = mean > 0.2 ? 'badge-success' : mean < -0.2 ? 'badge-danger' : 'badge-info';
      const row = document.createElement('tr');
      row.innerHTML = `<td title="${group.source}">${group.source}</td>` +
        `<td><span class="badge ${toneClass}">${mean.toFixed(1)}</span></td>` +
        `<td>${group.count}</td>` +
        `<td style="width:120px"><div class="score-bar"><div class="score-bar-fill score-medium" style="width:${Math.round(group.count / maximum * 100)}%"></div></div></td>`;
      return row;
    }));
  },

  severity(tone) {
    const n = Number(tone);
    if (!Number.isFinite(n)) return 'medium';
    if (n <= -4) return 'high';
    if (n < -1) return 'medium';
    return 'low';
  },

  renderEvents() {
    const container = document.getElementById('event-list');
    if (!container) return;
    const items = [...this.articles]
      .sort((a, b) => (this.parseDate(b.seendate)?.getTime() || 0) - (this.parseDate(a.seendate)?.getTime() || 0))
      .slice(0, 12);
    if (!items.length) {
      container.replaceChildren();
      const p = document.createElement('p');
      p.className = 'chart-empty';
      p.textContent = 'No events recorded in the latest snapshot. Next refresh is scheduled every 6 hours.';
      container.appendChild(p);
      return;
    }
    container.replaceChildren(...items.map(item => {
      const article = document.createElement('div');
      article.className = 'list-item';
      const link = document.createElement('a');
      link.className = 'list-item-copy';
      link.href = item.url || '#';
      link.target = '_blank';
      link.rel = 'noreferrer noopener';
      const title = document.createElement('div');
      title.className = 'list-item-title';
      title.textContent = this.cleanText(item.title || 'Untitled signal');
      const meta = document.createElement('div');
      meta.className = 'list-item-meta';
      meta.textContent = `${item.domain || item.source || 'Public source'} \u00b7 ${this.formatDate(item.seendate)}`;
      const badge = document.createElement('span');
      const sev = this.severity(item.tone);
      badge.className = `badge badge-${sev === 'high' ? 'danger' : sev === 'low' ? 'success' : 'warning'}`;
      badge.textContent = sev;
      link.append(title, meta);
      article.append(link, badge);
      return article;
    }));
  },

  renderSourceTags() {
    const container = document.getElementById('source-tags');
    if (!container) return;
    const labels = { news_articles: 'Google News RSS', cisa_catalog: 'CISA KEV', epss_frontier: 'FIRST EPSS' };
    const names = (this.data.meta && this.data.meta.sources) || Object.keys((this.data.live_data || {}));
    container.replaceChildren(...names.map(name => {
      const tag = document.createElement('span');
      tag.className = 'tag-source';
      tag.textContent = labels[name] || String(name).replaceAll('_', ' ');
      return tag;
    }));
  },

  renderGeneratedTime() {
    const el = document.getElementById('generated-time');
    if (el) el.textContent = this.formatDate(this.data.meta && this.data.meta.generated);
  },

  renderAnalysis() {
    const target = document.getElementById('llm-summary');
    if (!target) return;
    const supplied = this.cleanText((this.data && this.data.llm_summary) || '');
    if (supplied && !/pending api key|connect openrouter|demo mode|ground[- ]truth|news sample/i.test(supplied)) {
      target.textContent = supplied;
      return;
    }
    const leading = this.groupSources(this.articles).slice(0, 3).map(g => g.source).join(', ');
    const tone = this.meanTone(this.articles);
    const direction = tone > 0.2 ? 'positive' : tone < -0.2 ? 'negative' : 'near-neutral';
    target.textContent = this.articles.length
      ? `Current snapshot tracks ${this.articles.length} signals across ${this.uniqueDomains(this.articles)} domains. Coverage is led by ${leading || 'the available sources'}, with ${direction} mean reported news tone (${tone.toFixed(1)}).`
      : 'Signal analysis will populate automatically with the next data refresh.';
  },

  setupTabs() {
    const tabs = [...document.querySelectorAll('.nav-tab')];
    if (!tabs.length) return;
    const sections = tabs.map(tab => ({ tab, target: document.querySelector(tab.getAttribute('href')) }));
    tabs.forEach(tab => tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
    }));
    if (!('IntersectionObserver' in window)) return;
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        const match = sections.find(s => s.target === entry.target);
        if (!match) return;
        tabs.forEach(t => t.classList.remove('active'));
        match.tab.classList.add('active');
      });
    }, { rootMargin: '-40% 0px -50% 0px' });
    sections.forEach(s => { if (s.target) observer.observe(s.target); });
  },

  projectPoint(lng, lat) {
    const clamped = Math.max(this.LAT_BOTTOM, Math.min(this.LAT_TOP, lat));
    return [
      (lng + 180) / 360 * this.MAP_W,
      (this.LAT_TOP - clamped) / (this.LAT_TOP - this.LAT_BOTTOM) * this.MAP_H,
    ];
  },

  decodeTopoLand(topo) {
    const object = topo.objects && topo.objects.countries;
    if (!object) return '';
    const transform = topo.transform || { scale: [1, 1], translate: [0, 0] };
    const decodedArcs = topo.arcs.map(arc => {
      let x = 0, y = 0;
      return arc.map(pair => {
        x += pair[0]; y += pair[1];
        const lng = x * transform.scale[0] + transform.translate[0];
        const lat = y * transform.scale[1] + transform.translate[1];
        return [...this.projectPoint(lng, lat), lat];
      });
    });
    const ringPath = arcIndexes => {
      let points = [];
      arcIndexes.forEach(index => {
        const arc = index >= 0 ? decodedArcs[index] : decodedArcs[~index].slice().reverse();
        points = points.length ? points.concat(arc.slice(1)) : arc.slice();
      });
      if (points.length < 3 || points.every(p => p[2] < -58)) return '';
      const subpaths = [];
      let current = [points[0]];
      for (let i = 1; i < points.length; i++) {
        if (Math.abs(points[i][0] - points[i - 1][0]) > this.MAP_W * 0.5) {
          subpaths.push(current);
          current = [points[i]];
        } else {
          current.push(points[i]);
        }
      }
      subpaths.push(current);
      return subpaths
        .filter(sp => sp.length > 2)
        .map(sp => sp.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ') + ' Z')
        .join(' ');
    };
    const paths = [];
    const walk = geometry => {
      if (!geometry) return;
      if (geometry.type === 'Polygon') geometry.arcs.forEach(ring => paths.push(ringPath(ring)));
      else if (geometry.type === 'MultiPolygon') geometry.arcs.forEach(polygon => polygon.forEach(ring => paths.push(ringPath(ring))));
      else if (geometry.type === 'GeometryCollection') geometry.geometries.forEach(walk);
    };
    if (object.type === 'GeometryCollection') object.geometries.forEach(walk);
    else walk(object);
    return paths.join(' ');
  },

  async renderMap() {
    const container = document.getElementById('map');
    if (!container) return;
    const svg = this.svgElement('svg', { viewBox: `0 0 ${this.MAP_W} ${this.MAP_H}`, preserveAspectRatio: 'xMidYMid meet', 'aria-label': 'Activity map', role: 'img' });
    svg.append(this.svgElement('rect', { width: this.MAP_W, height: this.MAP_H, fill: '#040d15' }));
    let landPath = '';
    try {
      const response = await fetch('assets/world-110m.json');
      if (response.ok) landPath = this.decodeTopoLand(await response.json());
    } catch { landPath = ''; }
    if (landPath) {
      const land = this.svgElement('path', { d: landPath, class: 'land-path' });
      svg.append(land);
    } else {
      const label = this.svgElement('text', { x: this.MAP_W / 2, y: this.MAP_H / 2, class: 'map-label', 'text-anchor': 'middle' });
      label.textContent = 'Basemap unavailable \u2014 showing coverage points only';
      svg.append(label);
    }
    const markers = this.buildMarkers();
    if (!markers.length) {
      const empty = this.svgElement('text', { x: this.MAP_W / 2, y: this.MAP_H / 2 + 20, class: 'map-label', 'text-anchor': 'middle' });
      empty.textContent = 'No geolocated activity in the current snapshot.';
      svg.append(empty);
    }
    markers.forEach(marker => {
      const [x, y] = this.projectPoint(marker.lng, marker.lat);
      const group = this.svgElement('g');
      const pulse = this.svgElement('circle', { cx: x, cy: y, r: 8 + marker.r, class: 'signal-pulse' });
      const point = this.svgElement('circle', { cx: x, cy: y, r: marker.r, class: `signal-point ${marker.sev}` });
      const title = this.svgElement('title');
      title.textContent = marker.name;
      group.append(pulse, point, title);
      svg.append(group);
    });
    const caption = this.svgElement('text', { x: this.MAP_W * 0.02, y: this.MAP_H * 0.96, class: 'map-label' });
    caption.textContent = markers.length && !this.geoPoints.length
      ? 'Source cluster view \u00b7 current signal activity'
      : 'Geolocated coverage points \u00b7 Geolocated feed';
    svg.append(caption);
    container.replaceChildren(svg);
  },

  buildMarkers() {
    if (this.geoPoints.length) {
      const maxCount = Math.max(1, ...this.geoPoints.map(p => Number(p.count) || 1));
      return this.geoPoints.slice(0, 80).map(p => ({
        lng: Number(p.lon ?? p.lng),
        lat: Number(p.lat),
        r: 2.5 + 5 * Math.sqrt((Number(p.count) || 1) / maxCount),
        name: p.name || 'Coverage point',
        sev: 'point',
      }));
    }
    const palette = ['#ef4444', '#f59e0b', '#10b981', '#77b8cf'];
    return this.articles.slice(0, 16).map((article, i) => {
      const angle = i * 2.39996;
      return {
        lng: -10 + (i % 4) * 22 + Math.cos(angle) * 6,
        lat: 18 + (i % 5) * 9 + Math.sin(angle) * 4,
        r: 3.5,
        name: `${this.cleanText(article.domain || 'Public source')}: ${this.cleanText(article.title || '')}`,
        sev: this.severity(article.tone),
      };
    }).filter(m => Number.isFinite(m.lng) && Number.isFinite(m.lat));
  },

  async renderTimeline() {
    const container = document.getElementById('timeseries-chart');
    if (!container) return;
    const history = ((this.warning && this.warning.history) || [])
      .map(row => ({ date: this.parseDate(row.timestamp), value: Number(row.score) }))
      .filter(row => row.date && Number.isFinite(row.value))
      .sort((a, b) => a.date - b.date);
    if (!history.length) {
      const p = document.createElement('p');
      p.className = 'chart-empty';
      p.textContent = 'No accepted warning history is available.';
      container.replaceChildren(p);
      return;
    }
    const series = history.length === 1
      ? [{ date: new Date(history[0].date.getTime() - 21600000), value: history[0].value }, history[0]]
      : history;
    const width = Math.max(container.clientWidth || 600, 480);
    const height = 240;
    const margin = { top: 18, right: 18, bottom: 35, left: 34 };
    const max = 100;
    const x = i => margin.left + i * (width - margin.left - margin.right) / (series.length - 1);
    const y = v => height - margin.bottom - v / max * (height - margin.top - margin.bottom);
    const svg = this.svgElement('svg', { viewBox: `0 0 ${width} ${height}`, 'aria-label': 'Cyber exploitation warning score history', role: 'img' });
    [0, 0.5, 1].forEach(ratio => svg.append(this.svgElement('line', { x1: margin.left, x2: width - margin.right, y1: y(max * ratio), y2: y(max * ratio), class: 'chart-gridline' })));
    const area = `M${x(0)},${height - margin.bottom} ` + series.map((s, i) => `L${x(i)},${y(s.value)}`).join(' ') + ` L${x(series.length - 1)},${height - margin.bottom} Z`;
    svg.append(this.svgElement('path', { d: area, class: 'timeline-area' }));
    const line = series.map((s, i) => `${i ? 'L' : 'M'}${x(i)},${y(s.value)}`).join(' ');
    svg.append(this.svgElement('path', { d: line, class: 'timeline-line' }));
    series.forEach((s, i) => svg.append(this.svgElement('circle', { cx: x(i), cy: y(s.value), r: 4, class: 'timeline-point' })));
    const firstLabel = this.svgElement('text', { x: margin.left, y: height - 10, class: 'chart-label' });
    firstLabel.textContent = this.formatDate(series[0].date.toISOString());
    const lastLabel = this.svgElement('text', { x: width - margin.right, y: height - 10, class: 'chart-label', 'text-anchor': 'end' });
    lastLabel.textContent = this.formatDate(series[series.length - 1].date.toISOString());
    svg.append(firstLabel, lastLabel);
    container.replaceChildren(svg);
  },

  renderError(error) {
    this.injectStyles();
    const alert = document.querySelector('main .alert');
    if (alert) {
      alert.className = 'alert alert-danger';
      alert.replaceChildren();
      const strong = document.createElement('strong');
      strong.textContent = 'Dashboard unavailable: ';
      alert.append(strong, document.createTextNode(`${error instanceof Error ? error.message : 'data error'}. Values were not presented as live.`));
    }
    const generated = document.getElementById('generated-time');
    if (generated) generated.textContent = '\u2014';
    ['entity-rows', 'epss-rows'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<tr><td colspan="4" class="chart-empty">Data unavailable.</td></tr>';
    });
    ['event-list'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { const p = document.createElement('p'); p.className = 'chart-empty'; p.textContent = 'Data unavailable.'; el.replaceChildren(p); }
    });
    ['kev-radar', 'timeseries-chart', 'warning-components', 'warning-alerts'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { const p = document.createElement('p'); p.className = 'chart-empty'; p.textContent = 'Live data could not be loaded.'; el.replaceChildren(p); }
    });
  },

  svgElement(name, attributes = {}) {
    const element = document.createElementNS('http://www.w3.org/2000/svg', name);
    Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value));
    return element;
  },
};

document.addEventListener('DOMContentLoaded', () => INTEL.init());
