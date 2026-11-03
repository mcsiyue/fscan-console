/* ============================================================
   FSCAN 内网扫描台 · 前端逻辑
   ============================================================ */
(() => {
  'use strict';

  const TOKEN = (document.querySelector('meta[name="fscan-token"]') || {}).content || '';
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const DEFAULT_CONFIG = {
    target: '',
    target_file: '',
    exclude: '',
    mode: 'all',
    plugins: '',
    ports_preset: 'common',
    ports: '',
    threads: 600,
    timeout: 3,
    wt: 5,
    poc_num: 20,
    rate: 0,
    retry: 3,
    brute: true,
    poc: true,
    redis: true,
    no_ping: false,
    user: '',
    password: '',
    user_file: '',
    pass_file: '',
    hash: '',
    ssh_key: '',
    proxy: '',
    socks5: '',
    iface: '',
    custom_args: '',
    lang: 'zh',
    label: '',
  };

  const PORT_HINTS = {
    common: '内置 133 个高频端口，覆盖常见服务',
    web: 'Web 端口组：80 / 443 / 8080 / 8443 等',
    db: '数据库端口组：3306 / 1433 / 6379 / 27017 等',
    service: '常见服务端口组：21 / 22 / 445 / 3389 等',
    all: '1-65535 全端口，耗时较长，建议先做快速侦察',
    custom: '手动填写，支持逗号分隔与区间，例如 80,443,8000-8100',
  };

  const state = {
    boot: null,
    config: { ...DEFAULT_CONFIG },
    settings: {},
    view: 'scan',
    filter: 'all',
    query: '',
    expanded: new Set(),
    targetFile: '',
    scan: {
      id: null,
      status: 'idle',
      logCursor: 0,
      resultCursor: 0,
      results: new Map(),
      order: [],
      logCount: 0,
      stats: { hosts: 0, alive: 0, ports: 0, services: 0, web: 0, vulns: 0, total: 0 },
      summary: null,
      elapsed: 0,
      startedLocal: 0,
      cmd: '',
      error: '',
    },
    pollNonce: 0,
    history: [],
    historyDetail: {
      id: '',
      meta: null,
      stats: null,
      results: new Map(),
      order: [],
      expanded: new Set(),
      filter: 'all',
      loadSeq: 0,
    },
    lastPreview: '',
    radarSig: '',
    renderQueued: false,
    lastRender: 0,
    autoscroll: true,
  };

  /* ---------------- utils ---------------- */
  const esc = (value) => String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const toInt = (value, fallback = 0) => {
    const n = parseInt(value, 10);
    return Number.isFinite(n) ? n : fallback;
  };

  const pad = (n) => String(n).padStart(2, '0');
  const fmtClock = (seconds) => {
    const s = Math.max(0, Math.floor(seconds || 0));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return h > 0 ? `${pad(h)}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
  };
  const fmtDuration = (seconds) => {
    const s = Number(seconds || 0);
    if (s >= 60) return `${Math.floor(s / 60)}m ${pad(Math.floor(s % 60))}s`;
    return `${s.toFixed(1)}s`;
  };
  const clockOf = (iso) => {
    if (!iso) return '--:--:--';
    const m = /T(\d{2}:\d{2}:\d{2})/.exec(String(iso));
    if (m) return m[1];
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '--:--:--' : `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  const dateOf = (iso) => {
    if (!iso) return '未知时间';
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2})/.exec(String(iso));
    if (m) return `${m[1]}-${m[2]}-${m[3]} ${m[4]}`;
    return String(iso).replace('T', ' ').slice(0, 16);
  };

  function hostOf(target) {
    const t = String(target || '').trim();
    if (!t) return '';
    if (t.includes('://')) {
      try { return new URL(t).hostname || t; } catch (e) { return t; }
    }
    if (t.startsWith('[') && t.includes(']')) return t.slice(1, t.indexOf(']'));
    const m = /^(.*):(\d+)$/.exec(t);
    return m ? m[1] : t;
  }

  function portOf(rec) {
    const d = rec.details || {};
    if (d.port != null && d.port !== '') return d.port;
    const m = /:(\d+)$/.exec(rec.target || '');
    return m ? m[1] : '';
  }

  function riskMeta(rec) {
    const status = String(rec.status || '').toLowerCase();
    const d = rec.details || {};
    if (status.includes('weak_credential') || d.username) return { tag: '弱口令', cls: 'badge--critical', level: 4 };
    if (/ms17|ms17010|smbghost|eternalblue/.test(status)) return { tag: '高危', cls: 'badge--critical', level: 4 };
    if (status.includes('unauthorized') || status.includes('未授权')) return { tag: '未授权', cls: 'badge--vuln', level: 3 };
    if (status.includes('cve')) return { tag: '漏洞', cls: 'badge--vuln', level: 3 };
    return { tag: '风险', cls: 'badge--vuln', level: 2 };
  }

  function detailSummary(rec) {
    const d = rec.details || {};
    if (rec.type === 'VULN') {
      let text = rec.status || d.vulnerability || '风险';
      text = text.replace(/^weak_credential:\s*/i, '弱口令 ');
      return text;
    }
    if (rec.type === 'HOST') return `存活${d.protocol ? ` · ${d.protocol}` : ''}`;
    if (rec.type === 'PORT') return '端口开放';
    const parts = [];
    if (d.title) parts.push(d.title);
    if (d.url) parts.push(d.url);
    if (d.product) parts.push(d.product);
    if (d.banner) parts.push(String(d.banner).slice(0, 64));
    return parts[0] || d.service || '服务已识别';
  }

  function serviceMain(rec) {
    const d = rec.details || {};
    return d.service || d.product || d.plugin || (rec.type === 'SERVICE' ? 'unknown' : '—');
  }

  function serviceSub(rec) {
    const d = rec.details || {};
    const bits = [];
    if (d.product && d.product !== d.service) bits.push(d.product);
    if (d.title) bits.push(d.title);
    if (Array.isArray(d.fingerprints) && d.fingerprints.length) bits.push(d.fingerprints.slice(0, 3).join(' / '));
    if (d.status && rec.type === 'SERVICE') bits.push(`HTTP ${d.status}`);
    if (d.os) bits.push(d.os);
    return bits.join(' · ');
  }

  function highlight(text) {
    let s = esc(text);
    s = s.replace(/(https?:\/\/[^\s<>"']+)/g, '<span class="hl-url">$1</span>');
    s = s.replace(/\b(\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?)\b/g, '<span class="hl-ip">$1</span>');
    s = s.replace(/(MS17-010|MS17010|SMBGhost|CVE-\d{4}-\d+|CVE-\d+)/gi, '<span class="hl-sev">$1</span>');
    s = s.replace(/(弱口令|weak[ _-]?password|weak_credential|未授权访问|unauthorized)/gi, '<span class="hl-sev">$1</span>');
    return s;
  }

  /* ---------------- API ---------------- */
  async function api(path, options = {}) {
    const headers = Object.assign({ 'X-FSCAN-Token': TOKEN }, options.headers || {});
    if (options.body && typeof options.body === 'string') headers['Content-Type'] = 'application/json';
    const res = await fetch(path, Object.assign({}, options, { headers }));
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok || (data && data.ok === false)) {
      const message = (data && data.error) || `请求失败 (HTTP ${res.status})`;
      throw new Error(message);
    }
    return data || {};
  }

  function toast(message, kind = '') {
    const wrap = $('#toastWrap');
    const node = document.createElement('div');
    node.className = 'toast' + (kind === 'error' ? ' is-error' : kind === 'ok' ? ' is-ok' : '');
    node.innerHTML = `<svg class="icon"><use href="#${kind === 'error' ? 'i-close' : 'i-shield'}"/></svg><span>${esc(message)}</span>`;
    wrap.appendChild(node);
    setTimeout(() => {
      node.style.transition = 'opacity .25s, transform .25s';
      node.style.opacity = '0';
      node.style.transform = 'translateY(6px)';
      setTimeout(() => node.remove(), 260);
    }, 3200);
  }

  /* ---------------- config <-> DOM ---------------- */
  const FIELD_IDS = {
    target: 'target', exclude: 'exclude', mode: 'mode', plugins: 'plugins', ports: 'ports',
    threads: 'threadsNum', timeout: 'timeout', wt: 'wt', poc_num: 'pocNum', rate: 'rate',
    user: 'user', password: 'password', user_file: 'userFile', pass_file: 'passFile',
    hash: 'hash', ssh_key: 'sshKey', proxy: 'proxy', socks5: 'socks5', iface: 'iface',
    custom_args: 'customArgs', label: 'label',
  };

  function readConfig() {
    const cfg = { ...DEFAULT_CONFIG };
    Object.entries(FIELD_IDS).forEach(([key, id]) => {
      const el = document.getElementById(id);
      if (!el) return;
      cfg[key] = el.value.trim();
    });
    cfg.threads = toInt(cfg.threads, 600);
    cfg.timeout = toInt(cfg.timeout, 3);
    cfg.wt = toInt(cfg.wt, 5);
    cfg.poc_num = toInt(cfg.poc_num, 20);
    cfg.rate = toInt(cfg.rate, 0);
    cfg.brute = $('#brute').checked;
    cfg.poc = $('#poc').checked;
    cfg.redis = $('#redis').checked;
    cfg.no_ping = $('#noPing').checked;
    const active = $('#portPresets .is-active');
    cfg.ports_preset = active ? active.dataset.value : 'common';
    cfg.target_file = state.targetFile || '';
    cfg.exclude_file = '';
    return cfg;
  }

  function applyConfig(cfg) {
    if (!cfg) return;
    Object.entries(FIELD_IDS).forEach(([key, id]) => {
      const el = document.getElementById(id);
      if (!el) return;
      if (cfg[key] != null) el.value = cfg[key];
    });
    $('#brute').checked = cfg.brute !== false;
    $('#poc').checked = cfg.poc !== false;
    $('#redis').checked = cfg.redis !== false;
    $('#noPing').checked = !!cfg.no_ping;
    const preset = cfg.ports_preset || 'common';
    $$('#portPresets button').forEach((b) => b.classList.toggle('is-active', b.dataset.value === preset));
    state.targetFile = cfg.target_file || '';
    renderTargetFile();
    syncPortInputs();
    syncMode();
    syncThreads();
    updateRange();
  }

  function renderTargetFile() {
    const chip = $('#targetFileChip');
    if (!state.targetFile) {
      chip.hidden = true;
      return;
    }
    chip.hidden = false;
    const name = state.targetFile.split(/[\\/]/).pop() || 'targets.txt';
    $('#targetFileName').textContent = `已导入 ${name}`;
    $('#targetFileName').title = state.targetFile;
  }

  function syncPortInputs() {
    const active = $('#portPresets .is-active');
    const preset = active ? active.dataset.value : 'common';
    const input = $('#ports');
    input.disabled = preset !== 'custom';
    if (preset === 'custom') {
      input.placeholder = '80,443,8000-8100';
    } else {
      input.placeholder = preset === 'all' ? '1-65535' : '使用预设端口组';
    }
    $('#portHint').textContent = PORT_HINTS[preset] || '';
  }

  function syncMode() {
    const mode = $('#mode').value;
    const pluginInput = $('#plugins');
    pluginInput.hidden = mode !== 'plugin';
    const portsDisabled = mode === 'alive';
    $('#portPresets').classList.toggle('is-disabled', portsDisabled);
    $$('#portPresets button').forEach((b) => { b.disabled = portsDisabled; });
    if (portsDisabled) $('#ports').disabled = true;
    else syncPortInputs();
    if (mode === 'plugin' && !pluginInput.value) {
      $('#portHint').textContent = '指定插件会使用模块默认端口，可用自定义端口覆盖';
    }
  }

  function syncThreads() {
    const num = $('#threadsNum');
    const range = $('#threads');
    const value = Math.max(20, Math.min(2000, toInt(num.value, 600)));
    range.value = value;
    updateRange();
  }

  function updateRange() {
    const range = $('#threads');
    const pct = ((toInt(range.value, 600) - 20) / (2000 - 20)) * 100;
    range.style.setProperty('--p', `${Math.max(0, Math.min(100, pct))}%`);
  }

  let saveTimer = null;
  let previewTimer = null;
  function onConfigChanged() {
    state.config = readConfig();
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      try { localStorage.setItem('fscanDesk.config', JSON.stringify(state.config)); } catch (e) { /* ignore */ }
    }, 250);
    if (previewTimer) clearTimeout(previewTimer);
    previewTimer = setTimeout(updatePreview, 650);
  }

  function applyPreset(name) {
    if (name === 'recon') {
      applyConfig({
        ...readConfig(),
        mode: 'all', ports_preset: 'common', brute: false, poc: false, redis: false,
        threads: 400, timeout: 2, no_ping: false,
      });
      toast('已套用「快速侦察」：常用端口，关闭爆破与 POC');
    } else if (name === 'deep') {
      applyConfig({
        ...readConfig(),
        mode: 'all', ports_preset: 'common', brute: true, poc: true, redis: true,
        threads: 600, timeout: 3, wt: 5, poc_num: 20, rate: 0, no_ping: false,
      });
      toast('已套用「深度扫描」：全插件默认参数');
    } else if (name === 'alive') {
      applyConfig({ ...readConfig(), mode: 'alive' });
      toast('已套用「仅存活」：ICMP 快速探活');
    }
    onConfigChanged();
  }

  async function updatePreview() {
    const cfg = readConfig();
    if (!cfg.target && !cfg.target_file) {
      setPeek('填写目标后生成命令');
      state.lastPreview = '';
      return;
    }
    try {
      const data = await api('/api/preview', { method: 'POST', body: JSON.stringify(cfg) });
      state.lastPreview = data.cmd || '';
      setPeek(data.cmd || '');
    } catch (e) {
      setPeek(e.message);
    }
  }

  function setPeek(text) {
    const el = $('#cmdPeekText');
    const raw = String(text || '');
    let short = raw;
    if (raw) {
      let exePart = '';
      let rest = '';
      if (raw.startsWith('"')) {
        const end = raw.indexOf('"', 1);
        if (end > 0) {
          exePart = raw.slice(1, end);
          rest = raw.slice(end + 1);
        }
      }
      if (!exePart) {
        const idx = raw.indexOf(' ');
        exePart = idx > 0 ? raw.slice(0, idx) : raw;
        rest = idx > 0 ? raw.slice(idx) : '';
      }
      if (/[\\/]/.test(exePart)) short = exePart.split(/[\\/]/).pop() + rest;
    }
    el.textContent = short || '等待配置…';
    el.title = short || '';
  }

  /* ---------------- scan lifecycle ---------------- */
  function resetScanView(cmd = '') {
    state.scan.id = null;
    state.scan.logCursor = 0;
    state.scan.resultCursor = 0;
    state.scan.results = new Map();
    state.scan.order = [];
    state.scan.logCount = 0;
    state.scan.stats = { hosts: 0, alive: 0, ports: 0, services: 0, web: 0, vulns: 0, total: 0 };
    state.scan.summary = null;
    state.scan.elapsed = 0;
    state.scan.error = '';
    state.expanded.clear();
    clearConsoleNodes();
    if ($('#consoleEmpty')) $('#consoleEmpty').hidden = false;
    $('#resultBody').innerHTML = '';
    $('#radarBlips').innerHTML = '';
    state.radarSig = '';
    if (cmd) addSystemLog(`$ ${cmd}`);
    renderAll();
  }

  function clearConsoleNodes() {
    const consoleEl = $('#console');
    if (!consoleEl) return;
    $$('.log-line', consoleEl).forEach((node) => node.remove());
  }

  function setStatus(status, extra = {}) {
    state.scan.status = status;
    if (extra.error != null) state.scan.error = extra.error;
    const labels = {
      idle: '待命', starting: '启动中', running: '扫描中',
      done: '已完成', stopped: '已停止', error: '出错',
    };
    const cls = {
      idle: '', starting: 'is-running', running: 'is-running',
      done: 'is-done', stopped: 'is-stopped', error: 'is-error',
    }[status] || '';
    const runState = $('#runState');
    runState.className = `run-state ${cls}`.trim();
    $('#stateText').textContent = labels[status] || status;
    $('#statState').textContent = labels[status] || status;
    const dotCls = status === 'running' ? ' is-live' : status === 'done' ? ' is-done' : status === 'error' ? ' is-error' : '';
    $('#statDot').className = `state-dot${dotCls}`;
    $('#liveDot').classList.toggle('is-live', status === 'running' || status === 'starting');
    const radar = $('#radar');
    radar.classList.toggle('is-live', status === 'running');
    radar.classList.toggle('is-idle', status !== 'running');

    const btn = $('#btnStart');
    const label = $('#btnStartLabel');
    const iconUse = btn.querySelector('use');
    if (status === 'running' || status === 'starting') {
      btn.classList.add('is-stop');
      label.textContent = status === 'starting' ? '正在启动…' : '停止扫描';
      if (iconUse) iconUse.setAttribute('href', '#i-stop');
      btn.disabled = status === 'starting';
    } else {
      btn.classList.remove('is-stop');
      label.textContent = status === 'done' || status === 'stopped' || status === 'error' ? '再次扫描' : '开始扫描';
      if (iconUse) iconUse.setAttribute('href', '#i-play');
      btn.disabled = false;
    }
    const footer = $('#footerState');
    if (footer) {
      footer.textContent = {
        idle: '服务就绪', starting: '扫描启动中', running: '扫描进行中',
        done: '扫描完成', stopped: '扫描已停止', error: '扫描出错',
      }[status] || status;
    }
    updateHistoryLive();
    const radarMode = $('#radarMode');
    if (radarMode) {
      radarMode.textContent = {
        idle: 'IDLE', starting: 'ARMING', running: 'LIVE', done: 'DONE', stopped: 'STOPPED', error: 'ERROR',
      }[status] || '';
    }
    updateTimer();
  }

  async function startOrStop() {
    if (state.scan.status === 'running') {
      await stopScan();
      return;
    }
    if (state.scan.status === 'starting') return;
    await startScan();
  }

  async function startScan() {
    const cfg = readConfig();
    if (!cfg.target && !cfg.target_file) {
      toast('请先填写扫描目标', 'error');
      $('#target').focus();
      return;
    }
    if (!TOKEN || TOKEN === '__FSCAN_TOKEN__') {
      toast('请通过桌面启动器打开本程序', 'error');
      return;
    }
    setStatus('starting');
    const nonce = ++state.pollNonce;
    try {
      const res = await api('/api/scan/start', { method: 'POST', body: JSON.stringify(cfg) });
      resetScanView();
      state.scan.id = res.id;
      state.scan.startedLocal = Date.now();
      state.scan.status = 'running';
      setStatus('running');
      addSystemLog(`扫描已启动 · 任务 ${res.id}`);
      toast('扫描已启动', 'ok');
      pollLoop(res.id, nonce);
      saveLocalConfig(cfg);
    } catch (e) {
      setStatus('idle');
      toast(e.message, 'error');
    }
  }

  async function stopScan() {
    try {
      await api('/api/scan/stop', { method: 'POST', body: JSON.stringify({}) });
      toast('已发送停止信号');
      $('#btnStartLabel').textContent = '正在停止…';
      $('#btnStart').disabled = true;
    } catch (e) {
      toast(e.message, 'error');
      setStatus(state.scan.status);
    }
  }

  async function pollLoop(id, nonce) {
    if (nonce !== state.pollNonce) return;
    if (!state.scan.id || state.scan.id !== id) return;
    try {
      const data = await api(`/api/scan/poll?id=${encodeURIComponent(id)}&log=${state.scan.logCursor}&res=${state.scan.resultCursor}`);
      if (nonce !== state.pollNonce) return;
      handlePoll(data);
      if (data.status === 'running') {
        setTimeout(() => pollLoop(id, nonce), 480);
      } else {
        finishScan(data);
      }
    } catch (e) {
      if (nonce !== state.pollNonce) return;
      if (/扫描不存在|404/.test(e.message)) {
        setStatus('error', { error: '扫描任务已丢失，请重新开始' });
        addSystemLog(`无法继续获取任务状态：${e.message}`, true);
        toast('扫描任务已丢失', 'error');
        return;
      }
      state.scan.pollFails = (state.scan.pollFails || 0) + 1;
      if (state.scan.pollFails >= 3) {
        addSystemLog(`状态拉取失败：${e.message}`);
        state.scan.pollFails = 0;
      }
      setTimeout(() => pollLoop(id, nonce), 900);
    }
  }

  function handlePoll(data) {
    state.scan.pollFails = 0;
    if (Array.isArray(data.logs) && data.logs.length) {
      const frag = document.createDocumentFragment();
      data.logs.forEach((item) => {
        if (isBannerLine(item.text)) return;
        frag.appendChild(renderLogLine({ ...item, system: false }));
      });
      appendLogNodes(frag);
      state.scan.logCursor = data.next_log || state.scan.logCursor;
    }
    if (Array.isArray(data.results) && data.results.length) {
      mergeResults(data.results);
      state.scan.resultCursor = data.next_result || state.scan.resultCursor;
    }
    if (data.final && Array.isArray(data.all_results)) {
      replaceResults(data.all_results);
    }
    if (data.stats) state.scan.stats = data.stats;
    if (data.summary) state.scan.summary = data.summary;
    if (typeof data.elapsed === 'number') state.scan.elapsed = data.elapsed;
    if (data.status && data.status !== state.scan.status) setStatus(data.status, { error: data.error || '' });
    scheduleRender();
  }

  function finishScan(data) {
    if (data && data.stats) state.scan.stats = data.stats;
    if (data && data.summary) state.scan.summary = data.summary;
    if (data && typeof data.elapsed === 'number') state.scan.elapsed = data.elapsed;
    if (!state.scan.startedLocal) state.scan.startedLocal = Date.now() - (state.scan.elapsed || 0) * 1000;
    const status = (data && data.status) || state.scan.status;
    setStatus(status, { error: (data && data.error) || '' });
    if (status === 'done') {
      addSystemLog(`扫描完成 · 耗时 ${fmtDuration(state.scan.elapsed)} · ${state.scan.stats.ports} 端口 / ${state.scan.stats.services} 服务 / ${state.scan.stats.vulns} 风险`, true);
      toast(`扫描完成：${state.scan.stats.ports} 个端口，${state.scan.stats.vulns} 条风险`, 'ok');
    } else if (status === 'stopped') {
      addSystemLog('扫描已停止，已保留当前结果。');
      toast('扫描已停止');
    } else if (status === 'error') {
      addSystemLog(`扫描异常：${state.scan.error || '未知错误'}`, true);
      toast(state.scan.error || '扫描异常', 'error');
    }
    renderAll();
    loadHistory();
    setTimeout(updatePreview, 300);
  }

  function mergeResults(list) {
    list.forEach((rec) => {
      if (!rec || !rec.id) return;
      if (!state.scan.results.has(rec.id)) state.scan.order.push(rec.id);
      const previous = state.scan.results.get(rec.id);
      state.scan.results.set(rec.id, previous ? { ...previous, ...rec, details: { ...(previous.details || {}), ...(rec.details || {}) } } : rec);
    });
    scheduleRender();
  }

  function replaceResults(list) {
    const map = new Map();
    const order = [];
    list.forEach((rec) => {
      if (!rec || !rec.id) return;
      if (map.has(rec.id)) {
        const prev = map.get(rec.id);
        map.set(rec.id, { ...prev, ...rec, details: { ...(prev.details || {}), ...(rec.details || {}) } });
      } else {
        map.set(rec.id, rec);
        order.push(rec.id);
      }
    });
    state.scan.results = map;
    state.scan.order = order;
    scheduleRender();
  }

  /* ---------------- logging ---------------- */
  function classifyLog(text) {
    if (/^\[\+\]/.test(text)) return 'is-success';
    if (/^\[-\]/.test(text)) return 'is-error';
    if (/^\[!\]/.test(text)) return 'is-warn';
    if (/^\[\*\]/.test(text)) return 'is-info';
    if (/^[┌│└]/.test(text) || /^Fscan\s/.test(text)) return 'is-banner';
    return '';
  }

  function isBannerLine(text) {
    const value = String(text || '');
    return /^[┌│└]/.test(value) || /^\s*Fscan\s+\d/.test(value) || /^\s*$/.test(value);
  }

  function renderLogLine(item) {
    const text = String(item.text || '');
    const line = document.createElement('div');
    line.className = 'log-line ' + (item.system ? 'is-system' : classifyLog(text));
    const time = document.createElement('span');
    time.className = 'log-time';
    if (item.system) {
      time.textContent = 'SYS';
    } else if (item.t) {
      const d = new Date(Number(item.t) * 1000);
      time.textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    } else {
      time.textContent = '--:--:--';
    }
    const tag = document.createElement('span');
    tag.className = 'log-tag';
    const m = /^\[([+\-*!])\]\s?/.exec(text);
    tag.textContent = item.system ? '»' : (m ? m[1] : '');
    const msg = document.createElement('span');
    msg.className = 'log-msg';
    const body = m ? text.slice(m[0].length) : text;
    msg.innerHTML = highlight(body);
    line.append(time, tag, msg);
    return line;
  }

  function appendLogNodes(frag) {
    const consoleEl = $('#console');
    const added = frag.childNodes.length;
    if ($('#consoleEmpty')) $('#consoleEmpty').hidden = true;
    consoleEl.appendChild(frag);
    const nodes = consoleEl.children;
    if (nodes.length > 4000) {
      for (let i = 0; i < 800; i += 1) {
        if (nodes[0]) nodes[0].remove();
      }
    }
    state.scan.logCount += added;
    $('#logCount').textContent = `${state.scan.logCount} 行`;
    if (state.autoscroll) consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function addSystemLog(text, plain = false) {
    const node = renderLogLine({ text, t: Date.now() / 1000, system: true });
    if (plain) node.classList.add('is-success');
    const frag = document.createDocumentFragment();
    frag.appendChild(node);
    appendLogNodes(frag);
  }

  function clearConsole() {
    clearConsoleNodes();
    state.scan.logCount = 0;
    $('#logCount').textContent = '0 行';
    addSystemLog('控制台已清空');
  }

  /* ---------------- rendering: stats & lists ---------------- */
  function scheduleRender() {
    if (state.renderQueued) return;
    state.renderQueued = true;
    requestAnimationFrame(() => {
      state.renderQueued = false;
      renderAll();
    });
  }

  function renderAll() {
    renderStats();
    renderResults();
    renderHosts();
    renderRisks();
    renderRadar();
    updateTimer();
  }

  function renderStats() {
    const s = state.scan.stats || {};
    $('#statHosts').textContent = s.hosts || 0;
    $('#statPorts').textContent = s.ports || 0;
    $('#statServices').textContent = s.services || 0;
    $('#statVulns').textContent = s.vulns || 0;
    $('#statWebSub').textContent = `web ${s.web || 0}`;
    $('#statHostsSub').textContent = s.alive ? `alive ${s.alive}` : 'distinct hosts';
    const rc = $('#riskCount');
    rc.textContent = s.vulns || 0;
    rc.dataset.zero = (s.vulns || 0) === 0 ? '1' : '0';
    $('#hostCount').textContent = s.hosts || 0;
    $('#resultCount').textContent = state.scan.results.size;
    $('#radarCount').textContent = s.hosts || 0;
    const st = state.scan.status;
    $('#radarStatus').textContent = st === 'running' ? '扫描中' : st === 'done' ? '已完成' : st === 'stopped' ? '已停止' : st === 'error' ? '异常' : '等待扫描';
  }

  function filteredRecords() {
    const type = state.filter;
    const q = state.query.trim().toLowerCase();
    const out = [];
    state.scan.order.forEach((id) => {
      const rec = state.scan.results.get(id);
      if (!rec) return;
      if (type !== 'all' && rec.type !== type) return;
      if (q) {
        const hay = `${rec.target} ${rec.status} ${rec.type} ${JSON.stringify(rec.details || {})}`.toLowerCase();
        if (!hay.includes(q)) return;
      }
      out.push(rec);
    });
    return out;
  }

  function typeBadge(rec) {
    if (rec.type === 'VULN') {
      const meta = riskMeta(rec);
      return `<span class="badge ${meta.cls === 'badge--vuln' ? 'badge--vuln' : 'badge--critical'}">${esc(meta.tag)}</span>`;
    }
    const map = {
      HOST: ['主机', 'badge--host'],
      PORT: ['端口', 'badge--port'],
      SERVICE: ['服务', 'badge--service'],
    };
    const [label, cls] = map[rec.type] || ['信息', 'badge--service'];
    return `<span class="badge ${cls}">${label}</span>`;
  }

  function updateTabCounts() {
    const counts = { all: state.scan.results.size, HOST: 0, PORT: 0, SERVICE: 0, VULN: 0 };
    state.scan.results.forEach((rec) => { if (counts[rec.type] != null) counts[rec.type] += 1; });
    $$('#resultTabs .tab').forEach((tab) => {
      const key = tab.dataset.filter;
      tab.classList.toggle('is-active', key === state.filter);
      const span = tab.querySelector('span');
      if (span) span.textContent = counts[key] || 0;
    });
  }

  function buildResultRow(rec) {
    const port = portOf(rec);
    const tr = document.createElement('tr');
    tr.className = 'row';
    tr.dataset.id = rec.id;
    tr.innerHTML = `
      <td>${typeBadge(rec)}</td>
      <td class="mono" title="${esc(rec.target)}">${esc(hostOf(rec.target))}</td>
      <td class="mono">${esc(port || '—')}</td>
      <td>
        <span class="cell-main" title="${esc(serviceMain(rec))}">${esc(serviceMain(rec))}</span>
        ${serviceSub(rec) ? `<span class="cell-sub" title="${esc(serviceSub(rec))}">${esc(serviceSub(rec))}</span>` : ''}
      </td>
      <td class="detail-text" title="${esc(detailSummary(rec))}">${esc(detailSummary(rec))}</td>
      <td class="mono">${esc(clockOf(rec.time))}</td>
    `;
    return tr;
  }

  function renderResults() {
    updateTabCounts();
    const wrap = $('#tableWrap');
    const scrollTop = wrap.scrollTop;
    const rows = filteredRecords();
    const body = $('#resultBody');
    const frag = document.createDocumentFragment();
    rows.forEach((rec) => {
      const tr = buildResultRow(rec);
      if (state.expanded.has(rec.id)) {
        tr.classList.add('is-open');
        frag.appendChild(tr);
        frag.appendChild(buildDetailRow(rec));
      } else {
        frag.appendChild(tr);
      }
    });
    body.innerHTML = '';
    body.appendChild(frag);
    $('#resultEmpty').hidden = rows.length > 0;
    const total = state.scan.results.size;
    const emptyTitle = $('#resultEmpty').querySelector('p');
    const emptyText = $('#resultEmpty').querySelector('span');
    if (rows.length === 0) {
      if (state.query) {
        emptyTitle.textContent = '没有匹配的结果';
        emptyText.textContent = '换个关键词，或切换上方的类型筛选。';
      } else if (state.filter !== 'all' && total > 0) {
        emptyTitle.textContent = '当前类型没有结果';
        emptyText.textContent = '点击「全部」查看所有发现，或切换其他类型。';
      } else if (state.scan.status === 'running' || state.scan.status === 'starting') {
        emptyTitle.textContent = '正在等待结果';
        emptyText.textContent = '发现的主机、端口和服务会实时出现在这里。';
      } else if ((state.scan.status === 'done' || state.scan.status === 'stopped') && total === 0) {
        emptyTitle.textContent = '本次扫描没有发现结果';
        emptyText.textContent = '可以换一组端口、放宽目标范围，或先确认目标是否可达。';
      } else {
        emptyTitle.textContent = '等待扫描结果';
        emptyText.textContent = '开放端口、服务指纹、弱口令与漏洞会按发现顺序汇总到这里。';
      }
    }
    wrap.scrollTop = scrollTop;
    $('#resultCount').textContent = total;
  }

  function buildDetailRow(rec) {
    const tr = document.createElement('tr');
    tr.className = 'detail-row';
    tr.dataset.detailFor = rec.id;
    const d = rec.details || {};
    const keys = Object.keys(d).sort();
    const kvs = keys.map((key) => {
      let value = d[key];
      if (value == null || value === '') return '';
      if (Array.isArray(value)) value = value.join(', ');
      if (typeof value === 'object') value = JSON.stringify(value);
      const text = String(value);
      const short = text.length > 160 ? `${text.slice(0, 160)}…` : text;
      return `<div class="kv"><span>${esc(key)}</span><b title="${esc(text)}">${esc(short)}</b></div>`;
    }).join('');
    const raw = JSON.stringify(rec, null, 2);
    tr.innerHTML = `<td colspan="6"><div class="detail">
      <div class="detail-grid">${kvs || '<div class="kv"><span>detail</span><b>无附加字段</b></div>'}</div>
      <div class="detail-raw"><span>RAW JSON</span><pre>${esc(raw)}</pre></div>
    </div></td>`;
    return tr;
  }

  function renderHosts() {
    const groups = new Map();
    state.scan.results.forEach((rec) => {
      const host = hostOf(rec.target);
      if (!host) return;
      if (!groups.has(host)) groups.set(host, { host, ports: new Set(), services: 0, risks: 0, web: false });
      const g = groups.get(host);
      if (rec.type === 'PORT') g.ports.add(portOf(rec));
      if (rec.type === 'SERVICE') { g.services += 1; if (rec.details && rec.details.is_web) g.web = true; }
      if (rec.type === 'VULN') g.risks += 1;
    });
    const list = Array.from(groups.values())
      .sort((a, b) => (b.risks - a.risks) || (b.ports.size - a.ports.size) || a.host.localeCompare(b.host));
    const wrap = $('#hostList');
    if (!list.length) {
      wrap.innerHTML = '<div class="empty-mini">尚未发现主机</div>';
      return;
    }
    wrap.innerHTML = list.slice(0, 60).map((g) => `
      <div class="host-item" title="${esc(g.host)}">
        <i style="${g.risks ? 'background:var(--red);box-shadow:0 0 6px rgba(255,107,107,.8)' : g.web ? 'background:var(--cyan);box-shadow:0 0 6px rgba(90,216,230,.8)' : ''}"></i>
        <span class="host-name">${esc(g.host)}</span>
        <span class="host-meta">${g.ports.size} 端口${g.risks ? ` · ${g.risks} 风险` : ''}</span>
      </div>`).join('');
  }

  function renderRisks() {
    const risks = state.scan.order
      .map((id) => state.scan.results.get(id))
      .filter((rec) => rec && rec.type === 'VULN')
      .sort((a, b) => riskMeta(b).level - riskMeta(a).level);
    const wrap = $('#riskList');
    if (!risks.length) {
      wrap.innerHTML = '<div class="empty-mini">暂无风险发现</div>';
      return;
    }
    wrap.innerHTML = risks.slice(0, 30).map((rec) => {
      const meta = riskMeta(rec);
      const summary = detailSummary(rec);
      return `<div class="risk-item" title="${esc(`${rec.target} ${summary}`)}">
        <span class="risk-tag ${meta.tag === '弱口令' ? 'is-cred' : ''}">${esc(meta.tag)}</span>
        <span class="risk-text"><b>${esc(rec.target)}</b><span>${esc(summary)}</span></span>
      </div>`;
    }).join('');
  }

  function renderRadar() {
    const groups = new Map();
    state.scan.results.forEach((rec) => {
      const host = hostOf(rec.target);
      if (!host) return;
      if (!groups.has(host)) groups.set(host, { risk: false, web: false });
      const g = groups.get(host);
      if (rec.type === 'VULN') g.risk = true;
      if (rec.type === 'SERVICE' && rec.details && rec.details.is_web) g.web = true;
    });
    const hosts = Array.from(groups.keys()).sort();
    const sig = hosts.map((h) => {
      const g = groups.get(h);
      return `${h}${g.risk ? '!' : ''}${g.web ? 'w' : ''}`;
    }).join('|');
    if (sig === state.radarSig) return;
    state.radarSig = sig;
    const wrap = $('#radarBlips');
    wrap.innerHTML = '';
    hosts.slice(0, 64).forEach((host, index) => {
      let h = 2166136261;
      for (let i = 0; i < host.length; i += 1) {
        h ^= host.charCodeAt(i);
        h = Math.imul(h, 16777619);
      }
      const angle = (h % 360) * Math.PI / 180;
      const radius = 13 + ((h >>> 9) % 32);
      const x = 50 + Math.cos(angle) * radius;
      const y = 50 + Math.sin(angle) * radius;
      const g = groups.get(host);
      const blip = document.createElement('span');
      blip.className = 'blip' + (g.risk ? ' is-risk' : g.web ? ' is-web' : '');
      blip.style.left = `${x}%`;
      blip.style.top = `${y}%`;
      blip.style.animationDelay = `${(index % 8) * 40}ms`;
      blip.title = host;
      wrap.appendChild(blip);
    });
  }

  function updateTimer() {
    let elapsed = state.scan.elapsed || 0;
    if (state.scan.status === 'running' && state.scan.startedLocal) {
      elapsed = Math.max(elapsed, (Date.now() - state.scan.startedLocal) / 1000);
    }
    $('#timer').textContent = fmtClock(elapsed);
    $('#statElapsed').textContent = `elapsed ${fmtClock(elapsed)}`;
  }

  /* ---------------- history ---------------- */
  async function loadHistory() {
    try {
      const data = await api('/api/history');
      state.history = data.items || [];
      renderHistory();
    } catch (e) { /* silent */ }
  }

  function renderHistory() {
    const badge = $('#navHistoryBadge');
    if (badge) badge.textContent = state.history.length;
    const grid = $('#historyList');
    const empty = $('#historyEmpty');
    if (!state.history.length) {
      grid.innerHTML = '';
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    grid.innerHTML = state.history.map((item) => {
      const stats = item.stats || {};
      const status = item.status || 'done';
      const statusText = { done: '已完成', error: '出错', stopped: '已停止', running: '运行中' }[status] || status;
      const stateCls = status === 'error' ? 'is-error' : status === 'stopped' ? 'is-stopped' : '';
      const modeLabel = { all: '全量扫描', alive: '仅存活', web: 'Web 探测', plugin: '指定插件' }[item.mode] || item.mode || '';
      const portsLabel = {
        common: '常用端口', web: 'Web 端口', db: '数据库端口', service: '服务端口',
        all: '全端口', custom: '自定义端口',
      }[(item.cfg || {}).ports_preset] || '';
      const metaLine = [modeLabel, portsLabel, item.label].filter(Boolean).join(' · ');
      return `<article class="history-card" data-id="${esc(item.id)}">
        <div class="history-top">
          <span class="history-time">${esc(dateOf(item.started_at))}</span>
          <span class="history-state ${stateCls}"><i></i>${statusText}</span>
        </div>
        <div class="history-target" title="${esc(item.target || '')}">${esc(item.target || '未命名目标')}</div>
        <div class="history-label">${esc(metaLine || '未记录参数')}</div>
        <div class="history-stats">
          <span class="hstat">主机 <b>${stats.hosts || 0}</b></span>
          <span class="hstat">端口 <b>${stats.ports || 0}</b></span>
          <span class="hstat">服务 <b>${stats.services || 0}</b></span>
          <span class="hstat is-risk">风险 <b>${stats.vulns || 0}</b></span>
        </div>
        <div class="history-foot">
          <button class="text-btn" data-action="view">查看结果</button>
          <button class="text-btn" data-action="csv">CSV</button>
          <button class="text-btn" data-action="json">JSON</button>
          <button class="text-btn" data-action="folder">目录</button>
          <span class="spacer"></span>
          <span class="history-duration">${esc(fmtDuration(item.duration || 0))}</span>
          <button class="text-btn danger" data-action="delete" title="删除记录"><svg class="icon" style="width:13px;height:13px"><use href="#i-trash"/></svg></button>
        </div>
      </article>`;
    }).join('');
  }

  function openScanFolder(id) {
    const dataDir = (state.boot && state.boot.app && state.boot.app.data_dir) || '';
    const target = dataDir ? `${dataDir}\\scans\\${id}` : '';
    if (!target) {
      openDataFolder();
      return;
    }
    api('/api/open', { method: 'POST', body: JSON.stringify({ path: target }) })
      .catch((err) => toast(err.message, 'error'));
  }

  async function openHistoryDetail(id) {
    const seq = ++state.historyDetail.loadSeq;
    $('#hmTarget').textContent = '读取历史任务…';
    $('#hmMeta').textContent = id;
    $('#hmStats').innerHTML = '';
    $('#hmConsole').innerHTML = '<div class="empty-mini">读取中…</div>';
    $('#hmResultBody').innerHTML = '';
    $('#hmEmpty').hidden = true;
    openModal('historyModal');
    try {
      const [res, stored] = await Promise.all([
        api(`/api/scan/result?id=${encodeURIComponent(id)}`),
        api(`/api/history/get?id=${encodeURIComponent(id)}`),
      ]);
      if (seq !== state.historyDetail.loadSeq) return;
      const meta = stored.meta || {};
      const stats = res.stats || {};
      const detail = state.historyDetail;
      detail.id = id;
      detail.meta = meta;
      detail.stats = stats;
      detail.results = new Map();
      detail.order = [];
      detail.expanded = new Set();
      detail.filter = 'all';
      (res.results || []).forEach((rec) => {
        if (!rec || !rec.id) return;
        if (!detail.results.has(rec.id)) detail.order.push(rec.id);
        detail.results.set(rec.id, rec);
      });

      const statusText = {
        done: '已完成', error: '出错', stopped: '已停止', running: '运行中',
      }[res.status || meta.status || 'done'] || (res.status || meta.status || '已完成');
      const bits = [
        dateOf(meta.started_at),
        `耗时 ${fmtDuration(meta.duration || 0)}`,
        statusText,
        meta.label || '',
      ].filter(Boolean);
      $('#hmTarget').textContent = meta.target || '未命名目标';
      $('#hmTarget').title = meta.target || '';
      $('#hmMeta').textContent = bits.join(' · ');
      $('#hmStats').innerHTML = [
        ['主机', stats.hosts || 0, ''],
        ['开放端口', stats.ports || 0, ''],
        ['服务', stats.services || 0, ''],
        ['Web', stats.web || 0, ''],
        ['风险', stats.vulns || 0, 'is-risk'],
      ].map(([label, value, cls]) => `<div class="hm-stat ${cls}"><span>${label}</span><b>${value}</b></div>`).join('');

      const consoleText = stored.console || '';
      const lines = consoleText.split(/\r?\n/).filter((text) => text.trim() && !isBannerLine(text));
      const consoleEl = $('#hmConsole');
      consoleEl.innerHTML = '';
      if (lines.length) {
        const frag = document.createDocumentFragment();
        lines.slice(-3000).forEach((text) => {
          frag.appendChild(renderLogLine({ text, t: null, system: false }));
        });
        consoleEl.appendChild(frag);
        consoleEl.scrollTop = consoleEl.scrollHeight;
      } else {
        consoleEl.innerHTML = '<div class="empty-mini">没有控制台日志</div>';
      }
      $('#hmLogCount').textContent = `${lines.length} 行`;

      renderHistoryDetail();
    } catch (e) {
      if (seq !== state.historyDetail.loadSeq) return;
      toast(e.message, 'error');
      $('#hmMeta').textContent = e.message;
    }
  }

  function renderHistoryDetail() {
    const detail = state.historyDetail;
    const total = detail.results.size;
    const counts = { all: total, HOST: 0, PORT: 0, SERVICE: 0, VULN: 0 };
    detail.results.forEach((rec) => { if (counts[rec.type] != null) counts[rec.type] += 1; });
    $$('#hmTabs .tab').forEach((tab) => {
      const key = tab.dataset.filter;
      tab.classList.toggle('is-active', key === detail.filter);
      const span = tab.querySelector('span');
      if (span) span.textContent = counts[key] || 0;
    });

    const wrap = $('#hmTableWrap');
    const scrollTop = wrap ? wrap.scrollTop : 0;
    const rows = detail.order
      .map((rid) => detail.results.get(rid))
      .filter((rec) => rec && (detail.filter === 'all' || rec.type === detail.filter));
    const body = $('#hmResultBody');
    const frag = document.createDocumentFragment();
    rows.forEach((rec) => {
      const tr = buildResultRow(rec);
      if (detail.expanded.has(rec.id)) {
        tr.classList.add('is-open');
        frag.appendChild(tr);
        frag.appendChild(buildDetailRow(rec));
      } else {
        frag.appendChild(tr);
      }
    });
    body.innerHTML = '';
    body.appendChild(frag);
    const empty = $('#hmEmpty');
    empty.hidden = rows.length > 0;
    if (!rows.length) {
      const title = empty.querySelector('p');
      const text = empty.querySelector('span');
      if (total > 0 && detail.filter !== 'all') {
        title.textContent = '当前类型没有结果';
        text.textContent = '点击「全部」查看这条历史任务的完整结果。';
      } else {
        title.textContent = '这条记录没有结果';
        text.textContent = '可能扫描被提前停止，或目标没有发现。';
      }
    }
    $('#hmResultCount').textContent = rows.length === total ? `${total}` : `${rows.length} / ${total}`;
    if (wrap) wrap.scrollTop = scrollTop;
  }

  function toggleHistoryRow(id, tr) {
    const detail = state.historyDetail;
    const rec = detail.results.get(id);
    if (!rec) return;
    if (detail.expanded.has(id)) {
      detail.expanded.delete(id);
      tr.classList.remove('is-open');
      const next = tr.nextElementSibling;
      if (next && next.classList.contains('detail-row')) next.remove();
    } else {
      detail.expanded.add(id);
      tr.classList.add('is-open');
      tr.after(buildDetailRow(rec));
    }
  }

  async function deleteHistory(id) {
    if (!window.confirm('删除这条扫描记录？结果、日志与命令都会从本机删除。')) return;
    try {
      await api('/api/history/delete', { method: 'POST', body: JSON.stringify({ id }) });
      toast('记录已删除');
      loadHistory();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function download(kind, id) {
    const scanId = id || state.scan.id;
    if (!scanId) { toast('没有可导出的扫描结果', 'error'); return; }
    try {
      const res = await fetch(`/api/export?id=${encodeURIComponent(scanId)}&kind=${kind}`, {
        headers: { 'X-FSCAN-Token': TOKEN },
      });
      if (!res.ok) throw new Error(`导出失败 (HTTP ${res.status})`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const ext = kind === 'csv' ? 'csv' : kind === 'json' ? 'json' : 'log.txt';
      a.href = url;
      a.download = `fscan-${scanId}.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 8000);
      toast('导出已开始', 'ok');
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function openDataFolder() {
    try {
      await api('/api/open', { method: 'POST', body: JSON.stringify({}) });
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  /* ---------------- view / modal ---------------- */
  function switchView(view) {
    state.view = view;
    $$('.nav-item').forEach((b) => b.classList.toggle('is-active', b.dataset.view === view));
    $('#scanView').hidden = view !== 'scan';
    $('#historyView').hidden = view !== 'history';
    updateHistoryLive();
    if (view === 'history') loadHistory();
  }

  function updateHistoryLive() {
    const btn = $('#btnHistoryLive');
    if (!btn) return;
    const running = state.scan.status === 'running' || state.scan.status === 'starting';
    btn.hidden = !(running && state.view === 'history');
    if (running) btn.title = `当前任务已运行 ${fmtClock(state.scan.elapsed)}，点击回到扫描台`;
  }

  function openModal(id) {
    const modal = document.getElementById(id);
    if (!modal) return;
    modal.hidden = false;
    if (id === 'commandModal') {
      $('#cmdBlock').textContent = state.lastPreview || '暂无可执行命令';
    }
  }

  function closeModal(modal) {
    if (modal) modal.hidden = true;
  }

  function closeAllModals() {
    $$('.modal').forEach((m) => { m.hidden = true; });
  }

  async function showSettings() {
    const boot = state.boot || {};
    const fscan = boot.fscan || {};
    $('#setFscan').value = fscan.fscan_path || '';
    $('#setOpenMode').value = (boot.settings && boot.settings.open_mode) || 'app';
    $('#aboutVersion').textContent = `v${(boot.app && boot.app.version) || '1.0.0'}`;
    $('#fscanStatus').textContent = fscan.fscan_ok
      ? `已就绪 · Fscan ${fscan.fscan_version || '?'} · ${(fscan.plugins || []).length} 个插件`
      : '未找到 fscan.exe';
    $('#setDataDir').value = '%LOCALAPPDATA%\\FScanDesk';
    openModal('settingsModal');
  }

  async function saveSettings() {
    state.boot = state.boot || {};
    try {
      const data = await api('/api/settings', {
        method: 'POST',
        body: JSON.stringify({ fscan_path: $('#setFscan').value.trim(), open_mode: $('#setOpenMode').value }),
      });
      state.boot.fscan = data.fscan;
      state.boot.settings = data.settings;
      updateFscanLabels();
      toast('设置已保存', 'ok');
      closeAllModals();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function detectFscan() {
    state.boot = state.boot || {};
    const input = $('#setFscan').value.trim();
    $('#fscanStatus').textContent = '检测中…';
    try {
      const data = await api('/api/settings', { method: 'POST', body: JSON.stringify({ fscan_path: input }) });
      $('#setFscan').value = data.fscan.fscan_path || '';
      state.boot.fscan = data.fscan;
      updateFscanLabels();
      $('#fscanStatus').textContent = `已就绪 · Fscan ${data.fscan.fscan_version || '?'} · ${(data.fscan.plugins || []).length} 个插件`;
    } catch (e) {
      $('#fscanStatus').textContent = e.message;
    }
  }

  function updateFscanLabels() {
    const fscan = (state.boot && state.boot.fscan) || {};
    const ok = fscan.fscan_ok;
    $('#footerFscan').textContent = ok
      ? `fscan ${fscan.fscan_version || ''} · ${(fscan.plugins || []).length} plugins`
      : 'fscan 未就绪 · 请在设置中指定路径';
    $('#brandVersion').textContent = ok ? `v${fscan.fscan_version || '?'}` : 'v?';
  }

  /* ---------------- bootstrap ---------------- */
  function saveLocalConfig(cfg) {
    try { localStorage.setItem('fscanDesk.config', JSON.stringify(cfg)); } catch (e) { /* ignore */ }
  }

  function restoreLocalConfig() {
    try {
      const raw = localStorage.getItem('fscanDesk.config');
      if (raw) return JSON.parse(raw);
    } catch (e) { /* ignore */ }
    return null;
  }

  async function bootstrap() {
    try {
      const data = await api('/api/bootstrap');
      state.boot = data;
      state.settings = data.settings || {};
      updateFscanLabels();
      const local = restoreLocalConfig();
      const serverCfg = (data.settings && data.settings.last_config) || null;
      const initial = local || serverCfg || DEFAULT_CONFIG;
      state.config = { ...DEFAULT_CONFIG, ...initial };
      applyConfig(state.config);
      renderHistoryFrom(data.history || []);
      if (data.state && data.state.status === 'running') {
        state.scan.id = data.state.id;
        state.scan.startedLocal = Date.now() - (data.state.elapsed || 0) * 1000;
        resetScanView();
        state.scan.id = data.state.id;
        state.scan.cmd = data.state.cmd || '';
        setStatus('running');
        addSystemLog(`检测到正在运行的任务 ${data.state.id}，正在恢复输出…`);
        pollLoop(data.state.id, ++state.pollNonce);
      }
      updatePreview();
    } catch (e) {
      toast(`无法连接本地服务：${e.message}`, 'error');
    }
  }

  function renderHistoryFrom(items) {
    state.history = items || [];
    renderHistory();
  }

  /* ---------------- events ---------------- */
  function bindEvents() {
    $$('.nav-item').forEach((btn) => btn.addEventListener('click', () => switchView(btn.dataset.view)));
    $('#btnSettings').addEventListener('click', showSettings);
    $('#btnReset').addEventListener('click', () => {
      state.targetFile = '';
      applyConfig(DEFAULT_CONFIG);
      onConfigChanged();
      toast('配置已重置');
    });
    $$('#presets .preset').forEach((btn) => btn.addEventListener('click', () => applyPreset(btn.dataset.preset)));
    $$('#portPresets button').forEach((btn) => btn.addEventListener('click', () => {
      $$('#portPresets button').forEach((b) => b.classList.toggle('is-active', b === btn));
      syncPortInputs();
      onConfigChanged();
    }));
    $('#mode').addEventListener('change', () => { syncMode(); onConfigChanged(); });
    $('#threads').addEventListener('input', () => {
      $('#threadsNum').value = $('#threads').value;
      updateRange();
      onConfigChanged();
    });
    $('#threadsNum').addEventListener('input', () => { syncThreads(); onConfigChanged(); });
    ['target', 'exclude', 'plugins', 'ports', 'timeout', 'wt', 'pocNum', 'rate', 'user', 'password',
      'userFile', 'passFile', 'hash', 'sshKey', 'proxy', 'socks5', 'iface', 'customArgs', 'label']
      .forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', onConfigChanged);
      });
    ['brute', 'poc', 'redis', 'noPing'].forEach((id) => document.getElementById(id).addEventListener('change', onConfigChanged));
    $('#btnStart').addEventListener('click', startOrStop);
    $('#btnClearLog').addEventListener('click', clearConsole);
    $('#autoScroll').addEventListener('change', (e) => { state.autoscroll = e.target.checked; });
    $('#cmdPeek').addEventListener('click', async () => {
      if (!state.lastPreview) await updatePreview();
      openModal('commandModal');
    });
    $('#btnCopyCmd').addEventListener('click', () => copyText(state.lastPreview));
    $('#btnExportCsv').addEventListener('click', () => download('csv'));
    $('#btnExportJson').addEventListener('click', () => download('json'));
    $('#btnOpenData').addEventListener('click', openDataFolder);
    $('#btnHistoryLive').addEventListener('click', () => switchView('scan'));
    $('#btnOpenDataDir').addEventListener('click', openDataFolder);
    $('#btnSaveSettings').addEventListener('click', saveSettings);
    $('#btnDetect').addEventListener('click', detectFscan);
    $('#btnQuit').addEventListener('click', async () => {
      if (!window.confirm('退出 FSCAN 内网扫描台？正在运行的扫描会被停止。')) return;
      try { await api('/api/quit', { method: 'POST', body: JSON.stringify({}) }); } catch (e) { /* ignore */ }
      toast('程序已退出，可以关闭此页面');
    });
    $$('#resultTabs .tab').forEach((tab) => tab.addEventListener('click', () => {
      state.filter = tab.dataset.filter;
      renderResults();
    }));
    let searchTimer = null;
    $('#resultSearch').addEventListener('input', (e) => {
      if (searchTimer) clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state.query = e.target.value; renderResults(); }, 160);
    });
    $('#resultBody').addEventListener('click', (e) => {
      const tr = e.target.closest('tr.row');
      if (!tr) return;
      toggleRow(tr.dataset.id, tr);
    });
    $('#historyList').addEventListener('click', (e) => {
      const card = e.target.closest('.history-card');
      if (!card) return;
      const btn = e.target.closest('button[data-action]');
      const id = card.dataset.id;
      if (!btn) { openHistoryDetail(id); return; }
      const action = btn.dataset.action;
      if (action === 'view') openHistoryDetail(id);
      else if (action === 'delete') deleteHistory(id);
      else if (action === 'csv' || action === 'json') download(action, id);
      else if (action === 'folder') openScanFolder(id);
    });
    $('#hmTabs').addEventListener('click', (e) => {
      const tab = e.target.closest('.tab');
      if (!tab) return;
      state.historyDetail.filter = tab.dataset.filter;
      renderHistoryDetail();
    });
    $('#hmResultBody').addEventListener('click', (e) => {
      const tr = e.target.closest('tr.row');
      if (!tr) return;
      toggleHistoryRow(tr.dataset.id, tr);
    });
    $('#hmCsv').addEventListener('click', () => download('csv', state.historyDetail.id));
    $('#hmJson').addEventListener('click', () => download('json', state.historyDetail.id));
    $('#hmFolder').addEventListener('click', () => openScanFolder(state.historyDetail.id));
    $$('.modal').forEach((modal) => {
      modal.addEventListener('click', (e) => {
        if (e.target.closest('[data-close]')) closeModal(modal);
      });
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeAllModals();
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (document.querySelector('.modal:not([hidden])')) return;
        e.preventDefault();
        startOrStop();
      }
    });
    $('#btnImportTarget').addEventListener('click', () => $('#targetFileInput').click());
    $('#targetFileInput').addEventListener('change', uploadTargetFile);
    $('#btnClearTargetFile').addEventListener('click', () => {
      state.targetFile = '';
      renderTargetFile();
      onConfigChanged();
    });
  }

  function toggleRow(id, tr) {
    if (!id) return;
    const rec = state.scan.results.get(id);
    if (!rec) return;
    if (state.expanded.has(id)) {
      state.expanded.delete(id);
      tr.classList.remove('is-open');
      const next = tr.nextElementSibling;
      if (next && next.classList.contains('detail-row')) next.remove();
    } else {
      state.expanded.add(id);
      tr.classList.add('is-open');
      tr.after(buildDetailRow(rec));
    }
  }

  async function uploadTargetFile(event) {
    const file = event.target.files && event.target.files[0];
    event.target.value = '';
    if (!file) return;
    try {
      const res = await fetch(`/api/upload?name=${encodeURIComponent(file.name)}`, {
        method: 'POST',
        headers: { 'X-FSCAN-Token': TOKEN },
        body: file,
      });
      const data = await res.json();
      if (!res.ok || data.ok === false) throw new Error(data.error || '上传失败');
      state.targetFile = data.path;
      renderTargetFile();
      toast(`已导入 ${data.name}`, 'ok');
      onConfigChanged();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function copyText(text) {
    if (!text) { toast('没有可复制的内容'); return; }
    try {
      await navigator.clipboard.writeText(text);
      toast('已复制到剪贴板', 'ok');
    } catch (e) {
      const area = document.createElement('textarea');
      area.value = text;
      document.body.appendChild(area);
      area.select();
      try { document.execCommand('copy'); toast('已复制到剪贴板', 'ok'); }
      catch (err) { toast('复制失败', 'error'); }
      area.remove();
    }
  }

  function buildRadarTicks() {
    const group = $('#radarTicks');
    if (!group) return;
    const ns = 'http://www.w3.org/2000/svg';
    for (let i = 0; i < 36; i += 1) {
      const angle = (i * 10) * Math.PI / 180;
      const inner = i % 9 === 0 ? 98 : 103;
      const x1 = 120 + Math.cos(angle) * inner;
      const y1 = 120 + Math.sin(angle) * inner;
      const x2 = 120 + Math.cos(angle) * 108;
      const y2 = 120 + Math.sin(angle) * 108;
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', x1.toFixed(1));
      line.setAttribute('y1', y1.toFixed(1));
      line.setAttribute('x2', x2.toFixed(1));
      line.setAttribute('y2', y2.toFixed(1));
      group.appendChild(line);
    }
  }

  function heartbeat() {
    fetch('/api/heartbeat', { headers: { 'X-FSCAN-Token': TOKEN } }).catch(() => {});
  }

  function init() {
    bindEvents();
    buildRadarTicks();
    setStatus('idle');
    renderAll();
    bootstrap();
    setInterval(() => { updateTimer(); }, 1000);
    setInterval(heartbeat, 15000);
    setInterval(() => {
      if (state.view === 'history') loadHistory();
    }, 30000);
  }

  init();
})();
