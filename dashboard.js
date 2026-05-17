/* ═══════════════════════════════════════════════════════
   NLSIU Ambient Dashboard — dashboard.js
   Modular: this file owns all dashboard behaviour.
   Edit widgets here without touching index.html.
   ═══════════════════════════════════════════════════════ */

(function () {
  'use strict';

  /* ─────────────────────────────────────────────────────
     SHARED STORAGE KEYS  (must match index.html exactly)
  ───────────────────────────────────────────────────── */
  const TOKEN_KEY   = 'nlsiu_gtoken';
  const EXPIRY_KEY  = 'nlsiu_gexpiry';
  const REFRESH_KEY = 'nlsiu_grefresh';
  const MESS_KEY    = 'nlsiu_mess_data';
  const AUTH_FN     = '/api/auth';

  /* ─────────────────────────────────────────────────────
     STATE
  ───────────────────────────────────────────────────── */
  let _accessToken  = null;
  let _scheduleData = [];   // today's classes from Google Calendar
  let _deadlines    = [];   // upcoming events
  let _messData     = {};   // MESS JSON

  /* Timer state */
  const TIMER = {
    mode:        'pomodoro',   // 'pomodoro' | 'countdown'
    phase:       'focus',      // 'focus' | 'break' | 'long-break'
    pomoSession: 0,            // 0-3, resets after 4
    total:       25 * 60,      // seconds for current phase
    remaining:   25 * 60,
    running:     false,
    tick:        null,         // setInterval ref
    cdMinutes:   25,           // user-chosen countdown duration
  };

  const POMO_FOCUS      = 25 * 60;
  const POMO_BREAK      =  5 * 60;
  const POMO_LONG_BREAK = 15 * 60;

  /* ─────────────────────────────────────────────────────
     TOKEN HELPERS  (read-only — index.html writes them)
  ───────────────────────────────────────────────────── */
  function loadToken() {
    try {
      const token  = localStorage.getItem(TOKEN_KEY);
      const expiry = parseInt(localStorage.getItem(EXPIRY_KEY) || '0', 10);
      if (token && expiry && Date.now() < expiry) return token;
    } catch(e) {}
    return null;
  }
  function loadRefreshToken() {
    try { return localStorage.getItem(REFRESH_KEY) || null; } catch(e) { return null; }
  }
  function saveToken(token, expiresInSeconds) {
    const secs   = expiresInSeconds || 3600;
    const expiry = Date.now() + (secs - 120) * 1000;
    try {
      localStorage.setItem(TOKEN_KEY,  token);
      localStorage.setItem(EXPIRY_KEY, String(expiry));
    } catch(e) {}
  }
  async function silentRefresh() {
    const rt = loadRefreshToken();
    if (!rt) return null;
    try {
      const resp = await fetch(AUTH_FN, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ action: 'refresh', refresh_token: rt }),
      });
      if (resp.status === 401) return null;
      const data = await resp.json();
      if (data.access_token) {
        saveToken(data.access_token, data.expires_in);
        return data.access_token;
      }
    } catch(e) {}
    return null;
  }

  /* ─────────────────────────────────────────────────────
     OPEN / CLOSE
  ───────────────────────────────────────────────────── */
  function openDashboard() {
    const overlay = document.getElementById('ambient-overlay');
    if (!overlay) return;
    overlay.classList.add('open');
    document.body.classList.add('dash-open');
    document.body.style.overflow = 'hidden';
    initDashboard();
  }

  function closeDashboard() {
    const overlay = document.getElementById('ambient-overlay');
    if (!overlay) return;
    overlay.classList.remove('open');
    document.body.classList.remove('dash-open');
    document.body.style.overflow = '';
  }

  /* ─────────────────────────────────────────────────────
     INIT — called each time dashboard opens
  ───────────────────────────────────────────────────── */
  async function initDashboard() {
    startClock();
    initTimer();
    renderMess();

    // Try token from storage first
    _accessToken = loadToken();
    if (!_accessToken) {
      _accessToken = await silentRefresh();
    }

    if (_accessToken) {
      await Promise.all([
        fetchDeadlines(),
        fetchTodayClasses(),
      ]);
    } else {
      renderDeadlinesNoAuth();
      renderScheduleNoAuth();
    }
  }

  /* ─────────────────────────────────────────────────────
     1. CLOCK
  ───────────────────────────────────────────────────── */
  let _clockInterval = null;

  function startClock() {
    if (_clockInterval) clearInterval(_clockInterval);
    renderClock();
    _clockInterval = setInterval(renderClock, 1000);
  }

  function renderClock() {
    const now  = new Date();
    const h    = now.getHours();
    const m    = now.getMinutes();
    const ampm = h >= 12 ? 'pm' : 'am';
    const h12  = h % 12 || 12;
    const mm   = String(m).padStart(2, '0');

    const DAYS   = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
    const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    const day    = DAYS[now.getDay()];
    const date   = now.getDate();
    const month  = MONTHS[now.getMonth()];
    const year   = now.getFullYear();

    let greeting = 'Good morning';
    if (h >= 12 && h < 17) greeting = 'Good afternoon';
    else if (h >= 17)       greeting = 'Good evening';

    const clockEl    = document.getElementById('d-clock-time');
    const ampmEl     = document.getElementById('d-clock-ampm');
    const dateEl     = document.getElementById('d-clock-date');
    const greetingEl = document.getElementById('d-greeting');

    if (clockEl)    clockEl.textContent   = `${h12}:${mm}`;
    if (ampmEl)     ampmEl.textContent    = ampm;
    if (dateEl)     dateEl.textContent    = `${day}, ${date} ${month} ${year}`;
    if (greetingEl) greetingEl.textContent = greeting;
  }

  /* ─────────────────────────────────────────────────────
     2. FOCUS TIMER
  ───────────────────────────────────────────────────── */
  function initTimer() {
    // Don't reset if already running
    if (TIMER.running) return;
    renderTimerDisplay();
    renderTimerControls();
  }

  function setTimerMode(mode) {
    if (TIMER.running) stopTimer();
    TIMER.mode = mode;
    TIMER.phase = 'focus';
    TIMER.pomoSession = 0;
    if (mode === 'pomodoro') {
      TIMER.total = POMO_FOCUS;
      TIMER.remaining = POMO_FOCUS;
    } else {
      TIMER.total = TIMER.cdMinutes * 60;
      TIMER.remaining = TIMER.cdMinutes * 60;
    }
    renderTimerDisplay();
    renderTimerControls();

    // Update pill states
    document.querySelectorAll('.d-timer-pill').forEach(p => {
      p.classList.toggle('active', p.dataset.mode === mode);
    });
  }

  function startTimer() {
    if (TIMER.running) return;
    TIMER.running = true;
    TIMER.tick = setInterval(() => {
      TIMER.remaining--;
      if (TIMER.remaining <= 0) {
        onTimerEnd();
      } else {
        renderTimerDisplay();
      }
    }, 1000);
    renderTimerControls();
  }

  function pauseTimer() {
    TIMER.running = false;
    clearInterval(TIMER.tick);
    renderTimerControls();
  }

  function stopTimer() {
    TIMER.running = false;
    clearInterval(TIMER.tick);
    // Reset to current phase start
    if (TIMER.mode === 'pomodoro') {
      TIMER.remaining = TIMER.total;
    } else {
      TIMER.total = TIMER.cdMinutes * 60;
      TIMER.remaining = TIMER.cdMinutes * 60;
    }
    renderTimerDisplay();
    renderTimerControls();
  }

  function onTimerEnd() {
    TIMER.running = false;
    clearInterval(TIMER.tick);
    playChime();
    flashTimer();

    if (TIMER.mode === 'pomodoro') {
      TIMER.pomoSession++;
      if (TIMER.pomoSession >= 4) {
        TIMER.pomoSession = 0;
        TIMER.phase = 'long-break';
        TIMER.total = POMO_LONG_BREAK;
        TIMER.remaining = POMO_LONG_BREAK;
      } else if (TIMER.phase === 'focus') {
        TIMER.phase = 'break';
        TIMER.total = POMO_BREAK;
        TIMER.remaining = POMO_BREAK;
      } else {
        TIMER.phase = 'focus';
        TIMER.total = POMO_FOCUS;
        TIMER.remaining = POMO_FOCUS;
      }
    } else {
      TIMER.remaining = 0;
    }
    renderTimerDisplay();
    renderTimerControls();
  }

  function adjustCountdown(delta) {
    if (TIMER.running) return;
    TIMER.cdMinutes = Math.max(1, Math.min(180, TIMER.cdMinutes + delta));
    TIMER.total = TIMER.cdMinutes * 60;
    TIMER.remaining = TIMER.cdMinutes * 60;
    renderTimerDisplay();
  }

  function renderTimerDisplay() {
    const m = Math.floor(TIMER.remaining / 60);
    const s = TIMER.remaining % 60;
    const timeStr = `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;

    const timeEl = document.getElementById('d-timer-time');
    if (timeEl) timeEl.textContent = timeStr;

    // Ring progress
    const ring = document.getElementById('d-ring-progress');
    if (ring) {
      const R   = 48;
      const circ = 2 * Math.PI * R;
      const frac = TIMER.total > 0 ? TIMER.remaining / TIMER.total : 0;
      ring.style.strokeDasharray  = circ;
      ring.style.strokeDashoffset = circ * (1 - frac);
    }

    // Pomodoro session dots
    const dotsEl = document.getElementById('d-pomo-dots');
    if (dotsEl) {
      dotsEl.style.display = TIMER.mode === 'pomodoro' ? 'flex' : 'none';
      dotsEl.innerHTML = [0,1,2,3].map(i =>
        `<div class="d-pomo-dot${i < TIMER.pomoSession ? ' done' : ''}"></div>`
      ).join('');
    }

    // Countdown adjust row
    const cdRow = document.getElementById('d-countdown-row');
    if (cdRow) {
      cdRow.style.display = (TIMER.mode === 'countdown' && !TIMER.running) ? 'flex' : 'none';
      const durVal = document.getElementById('d-dur-val');
      if (durVal) durVal.textContent = `${TIMER.cdMinutes} min`;
    }

    // Phase label
    const phaseEl = document.getElementById('d-pomo-phase');
    if (phaseEl) {
      if (TIMER.mode === 'pomodoro') {
        const labels = { focus: 'Focus', break: 'Short break', 'long-break': 'Long break' };
        phaseEl.textContent = labels[TIMER.phase] || '';
      } else {
        phaseEl.textContent = '';
      }
    }
  }

  function renderTimerControls() {
    const wrap = document.getElementById('d-timer-controls');
    if (!wrap) return;

    if (TIMER.running) {
      wrap.innerHTML = `
        <button class="d-timer-btn" onclick="window._dash.pauseTimer()">Pause</button>
        <button class="d-timer-btn" onclick="window._dash.stopTimer()">Reset</button>`;
    } else if (TIMER.remaining < TIMER.total && TIMER.remaining > 0) {
      wrap.innerHTML = `
        <button class="d-timer-btn primary" onclick="window._dash.startTimer()">Resume</button>
        <button class="d-timer-btn" onclick="window._dash.stopTimer()">Reset</button>`;
    } else {
      wrap.innerHTML = `
        <button class="d-timer-btn primary" onclick="window._dash.startTimer()">Start</button>`;
    }
  }

  /* Chime — synthesised soft bell via Web Audio */
  function playChime() {
    try {
      const ctx  = new (window.AudioContext || window.webkitAudioContext)();
      const freqs = [523, 659, 784];
      freqs.forEach((freq, i) => {
        const osc  = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.type = 'sine';
        osc.frequency.value = freq;
        const t0 = ctx.currentTime + i * 0.22;
        gain.gain.setValueAtTime(0, t0);
        gain.gain.linearRampToValueAtTime(0.18, t0 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, t0 + 1.2);
        osc.start(t0);
        osc.stop(t0 + 1.3);
      });
    } catch(e) {}
  }

  function flashTimer() {
    const ring = document.querySelector('.d-timer-ring-wrap');
    if (ring) {
      ring.classList.add('d-timer-done-flash');
      setTimeout(() => ring.classList.remove('d-timer-done-flash'), 1800);
    }
  }

  /* ─────────────────────────────────────────────────────
     3. MESS MENU
  ───────────────────────────────────────────────────── */
  const MEAL_ORDER = ['breakfast','lunch','snacks','dinner'];
  const MEAL_ICONS = { breakfast:'☀️', lunch:'🍱', snacks:'☕', dinner:'🌙' };

  // Meal time windows for "live" detection (24h format)
  const MEAL_WINDOWS = {
    breakfast: [7*60+30,  9*60+30],
    lunch:     [12*60+30, 14*60+30],
    snacks:    [16*60,    18*60],
    dinner:    [19*60,    21*60],
  };

  function todayKey() {
    const n = new Date();
    const y = n.getFullYear();
    const m = String(n.getMonth() + 1).padStart(2, '0');
    const d = String(n.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }

  function loadMess() {
    try {
      const s = localStorage.getItem(MESS_KEY);
      if (s) return JSON.parse(s);
    } catch(e) {}
    return {};
  }

  function nowMinutes() {
    const n = new Date();
    return n.getHours() * 60 + n.getMinutes();
  }

  /* Returns current and next meal info objects or nulls */
  function getCurrentAndNext(mess) {
    const key  = todayKey();
    const data = mess[key];
    const now  = nowMinutes();
    let current = null;
    let next    = null;

    if (!data) return { current: null, next: null };

    for (const mealKey of MEAL_ORDER) {
      const meal   = data[mealKey];
      if (!meal) continue;
      const [start, end] = MEAL_WINDOWS[mealKey] || [0, 0];

      if (now >= start && now <= end) {
        current = { mealKey, meal, live: true };
      } else if (now < start && !next) {
        next = { mealKey, meal, live: false };
      }
    }

    // If no next found today, try tomorrow
    if (!next) {
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      const tKey  = tomorrow.toISOString().slice(0, 10);
      const tData = mess[tKey];
      if (tData) {
        const firstKey = MEAL_ORDER.find(k => tData[k]);
        if (firstKey) next = { mealKey: firstKey, meal: tData[firstKey], live: false, tomorrow: true };
      }
    }

    return { current, next };
  }

  function getMainItems(meal, maxItems = 3) {
    if (!meal || !meal.sections) return '';
    const all = [];
    for (const items of Object.values(meal.sections)) {
      all.push(...items);
      if (all.length >= maxItems) break;
    }
    return all.slice(0, maxItems).join(' · ');
  }

  function renderMess() {
    const wrap = document.getElementById('d-mess-wrap');
    if (!wrap) return;
    _messData = loadMess();
    const { current, next } = getCurrentAndNext(_messData);

    if (!current && !next) {
      wrap.innerHTML = '<div class="d-mess-empty">No mess menu data.<br>Upload a menu in the main portal.</div>';
      return;
    }

    let html = '<div class="d-mess-meals">';

    if (current) {
      const items = getMainItems(current.meal);
      html += `
        <div class="d-mess-row live">
          <div class="d-mess-icon">${MEAL_ICONS[current.mealKey] || '🍽️'}</div>
          <div class="d-mess-info">
            <div class="d-mess-name">${esc(current.meal.name)}</div>
            <div class="d-mess-time">${esc(current.meal.time)}</div>
            ${items ? `<div class="d-mess-items">${esc(items)}</div>` : ''}
          </div>
          <div class="d-mess-badge live">Serving</div>
        </div>`;
    }

    if (next) {
      const items = getMainItems(next.meal);
      const label = next.tomorrow ? 'Tomorrow' : 'Up next';
      html += `
        <div class="d-mess-row next">
          <div class="d-mess-icon">${MEAL_ICONS[next.mealKey] || '🍽️'}</div>
          <div class="d-mess-info">
            <div class="d-mess-name">${esc(next.meal.name)}</div>
            <div class="d-mess-time">${esc(next.meal.time)}</div>
            ${items ? `<div class="d-mess-items">${esc(items)}</div>` : ''}
          </div>
          <div class="d-mess-badge next">${label}</div>
        </div>`;
    }

    html += '</div>';
    wrap.innerHTML = html;
  }

  /* ─────────────────────────────────────────────────────
     4. DEADLINES  (reads from Deadlines & Office Hours cals)
  ───────────────────────────────────────────────────── */
  async function fetchDeadlines() {
    const wrap = document.getElementById('d-deadlines-wrap');
    if (!wrap) return;
    wrap.innerHTML = '<div class="d-loading"><div class="d-spinner"></div> Loading…</div>';

    try {
      // Find deadline / office-hours calendars
      const listResp = await fetch(
        'https://www.googleapis.com/calendar/v3/users/me/calendarList',
        { headers: { Authorization: 'Bearer ' + _accessToken } }
      );
      const listData = await listResp.json();
      if (listData.error) throw new Error(listData.error.message);

      let deadCal = null, officeCal = null;
      for (const c of (listData.items || [])) {
        const s = (c.summary || '').toLowerCase();
        if (!deadCal   && s.includes('deadline')) deadCal   = c.id;
        if (!officeCal && s.includes('office'))   officeCal = c.id;
      }

      const now  = new Date();
      const tMin = now.toISOString();
      const tMax = new Date(now.getTime() + 90 * 86400000).toISOString();

      const fetches = [];
      if (deadCal)   fetches.push(fetchCalBatch(deadCal,   'deadline', tMin, tMax));
      if (officeCal) fetches.push(fetchCalBatch(officeCal, 'office',   tMin, tMax));

      const results = (await Promise.all(fetches)).flat();
      results.sort((a,b) => new Date(a.startRaw) - new Date(b.startRaw));
      _deadlines = results.filter(e => new Date(e.startRaw) >= now);

      renderDeadlines(_deadlines.slice(0, 5));
    } catch(e) {
      wrap.innerHTML = '<div class="d-empty">Could not load deadlines.</div>';
    }
  }

  async function fetchCalBatch(calId, calType, tMin, tMax) {
    try {
      const r = await fetch(
        `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events?` +
        `timeMin=${tMin}&timeMax=${tMax}&singleEvents=true&orderBy=startTime&maxResults=30`,
        { headers: { Authorization: 'Bearer ' + _accessToken } }
      );
      const d = await r.json();
      if (d.error) return [];
      return (d.items || []).map(ev => {
        const allDay   = !ev.start.dateTime;
        const startRaw = ev.start.dateTime || ev.start.date;
        // Parse "CourseName / Component" format
        const sum = ev.summary || '';
        const sep = sum.indexOf(' / ');
        const component  = sep === -1 ? sum.trim() : sum.slice(sep + 3).trim();
        const courseName = sep === -1 ? '' : sum.slice(0, sep).trim();
        return { component, courseName, calType, startRaw, allDay, id: ev.id };
      });
    } catch { return []; }
  }

  function renderDeadlines(events) {
    const wrap = document.getElementById('d-deadlines-wrap');
    if (!wrap) return;
    if (!events.length) {
      wrap.innerHTML = '<div class="d-empty">No upcoming deadlines<br>in the next 90 days.</div>';
      return;
    }
    const now  = new Date();
    const DAYS = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    const MONS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

    wrap.innerHTML = '<div class="d-dl-list">' + events.map((ev, i) => {
      const start   = new Date(ev.startRaw);
      const isToday = start.toDateString() === now.toDateString();
      const timeStr = ev.allDay ? 'All day' : fmtTime(ev.startRaw);
      const todayBadge = isToday ? '<span class="d-dl-today-pill">Today</span>' : '';
      return `<div class="d-dl-item" style="animation-delay:${i*0.06}s">
        <div class="d-dl-date-col">
          <div class="d-dl-day-num">${start.getDate()}</div>
          <div class="d-dl-day-name">${DAYS[start.getDay()]}</div>
          <div class="d-dl-day-month">${MONS[start.getMonth()]}</div>
        </div>
        <div class="d-dl-dot ${ev.calType}"></div>
        <div class="d-dl-info">
          <div class="d-dl-title">${esc(ev.component)}${todayBadge}</div>
          ${ev.courseName ? `<div class="d-dl-course">${esc(ev.courseName)}</div>` : ''}
          <div class="d-dl-time">${timeStr}</div>
          <span class="d-dl-badge ${ev.calType}">${ev.calType === 'deadline' ? 'Deadline' : 'Office Hours'}</span>
        </div>
      </div>`;
    }).join('') + '</div>';
  }

  function renderDeadlinesNoAuth() {
    const wrap = document.getElementById('d-deadlines-wrap');
    if (wrap) wrap.innerHTML = '<div class="d-empty">Sign in via the main portal<br>to see deadlines.</div>';
  }

  /* ─────────────────────────────────────────────────────
     5. CLASS SCHEDULE  (primary calendar, today's events)
  ───────────────────────────────────────────────────── */
  const CLASS_KEYWORDS = ['labour','competition','drafting','dpc','adr','dispute','conveyancing','class','lecture','seminar','tutorial','law'];

  function looksLikeClass(summary) {
    const s = (summary || '').toLowerCase();
    return CLASS_KEYWORDS.some(k => s.includes(k));
  }

  async function fetchTodayClasses() {
    const wrap = document.getElementById('d-schedule-wrap');
    if (!wrap) return;
    wrap.innerHTML = '<div class="d-loading"><div class="d-spinner"></div> Loading…</div>';

    try {
      const now   = new Date();
      const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const end   = new Date(start.getTime() + 86400000);
      const tMin  = start.toISOString();
      const tMax  = end.toISOString();

      const r = await fetch(
        `https://www.googleapis.com/calendar/v3/calendars/primary/events?` +
        `timeMin=${tMin}&timeMax=${tMax}&singleEvents=true&orderBy=startTime&maxResults=50`,
        { headers: { Authorization: 'Bearer ' + _accessToken } }
      );
      const d = await r.json();
      if (d.error) throw new Error(d.error.message);

      // Filter to class-like events (non-all-day and matching keywords, or all timed events)
      let items = (d.items || []).filter(ev => ev.start.dateTime);
      // prefer keyword match, fall back to all timed if nothing matched
      const matched = items.filter(ev => looksLikeClass(ev.summary));
      if (matched.length) items = matched;

      _scheduleData = items.map(ev => ({
        title:    ev.summary || 'Class',
        location: ev.location || '',
        startRaw: ev.start.dateTime,
        endRaw:   ev.end?.dateTime || '',
      }));

      renderSchedule(_scheduleData);
    } catch(e) {
      const wrap = document.getElementById('d-schedule-wrap');
      if (wrap) wrap.innerHTML = '<div class="d-empty">Could not load schedule.</div>';
    }
  }

  function renderSchedule(classes) {
    const wrap = document.getElementById('d-schedule-wrap');
    if (!wrap) return;

    if (!classes.length) {
      const d = new Date();
      const DAYS = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
      wrap.innerHTML = `<div class="d-empty">No classes found for<br>${DAYS[d.getDay()]}.</div>`;
      return;
    }

    const now = new Date();
    const DAYS = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
    const d    = new Date();
    const dayLabel = DAYS[d.getDay()];

    let html = `<div class="d-sched-day-label">${dayLabel}</div><div class="d-sched-list">`;
    html += classes.map((cls, i) => {
      const start  = new Date(cls.startRaw);
      const end    = cls.endRaw ? new Date(cls.endRaw) : null;
      const isNow  = now >= start && end && now <= end;
      const dot    = isNow ? 'ongoing' : '';
      const nowPill = isNow ? '<span class="d-sched-now-pill">Now</span>' : '';
      return `<div class="d-sched-item" style="animation-delay:${i*0.06}s">
        <div class="d-sched-time-col">
          <div class="d-sched-start">${fmtTime(cls.startRaw)}</div>
          ${end ? `<div class="d-sched-end">${fmtTime(cls.endRaw)}</div>` : ''}
        </div>
        <div class="d-sched-dot ${dot}"></div>
        <div class="d-sched-info">
          <div class="d-sched-title">${esc(cls.title)}${nowPill}</div>
          ${cls.location ? `<div class="d-sched-loc">${esc(cls.location)}</div>` : ''}
        </div>
      </div>`;
    }).join('');
    html += '</div>';
    wrap.innerHTML = html;
  }

  function renderScheduleNoAuth() {
    const wrap = document.getElementById('d-schedule-wrap');
    if (wrap) wrap.innerHTML = '<div class="d-empty">Sign in via the main portal<br>to see today\'s schedule.</div>';
  }

  /* ─────────────────────────────────────────────────────
     UTILS
  ───────────────────────────────────────────────────── */
  function esc(s) {
    return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmtTime(raw) {
    if (!raw) return '';
    const d = new Date(raw);
    const h = d.getHours(), m = d.getMinutes();
    const ampm = h >= 12 ? 'pm' : 'am';
    return `${h % 12 || 12}:${String(m).padStart(2,'0')} ${ampm}`;
  }

  /* ─────────────────────────────────────────────────────
     KEYBOARD
  ───────────────────────────────────────────────────── */
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeDashboard();
  });

  /* ─────────────────────────────────────────────────────
     PUBLIC API  (called from HTML event handlers)
  ───────────────────────────────────────────────────── */
  window._dash = {
    open:            openDashboard,
    close:           closeDashboard,
    startTimer:      startTimer,
    pauseTimer:      pauseTimer,
    stopTimer:       stopTimer,
    setTimerMode:    setTimerMode,
    adjustCountdown: adjustCountdown,
  };

})();
