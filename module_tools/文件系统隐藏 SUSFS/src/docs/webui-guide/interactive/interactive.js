/* Interactive, offline lesson shell. The iframe is the unmodified production WebUI
 * served beside a memory-only simulator. It never talks to the device. */
(function () {
  'use strict';
  const $ = id => id.startsWith('.') ? document.querySelector(id) : document.getElementById(id);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const lessons = window.GuideLessons?.lessons || [];
  const prefsKey = 'susfs-guide-interactive-v1';
  const icons = {
    spark:'<path d="m12 2 1.7 6.3L20 10l-6.3 1.7L12 18l-1.7-6.3L4 10l6.3-1.7L12 2Z"/><path d="m19 16 .7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7L19 16Z"/>',
    settings:'<path d="M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1 1-3Z"/><circle cx="12" cy="12" r="3"/>',
    arrow:'<path d="M5 12h14M13 6l6 6-6 6"/>', back:'<path d="m15 18-6-6 6-6M9 12h12"/>', x:'<path d="m6 6 12 12M18 6 6 18"/>', search:'<circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/>', book:'<path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v17H6.5A2.5 2.5 0 0 0 4 21.5v-17Z"/><path d="M4 19h16M8 6h8M8 10h8"/>', lightbulb:'<path d="M9 18h6M10 22h4M8.5 14.5A6 6 0 1 1 15.5 14c-.9.7-1.5 1.5-1.5 2.5h-4c0-1-.6-1.7-1.5-2Z"/>', locate:'<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>', more:'<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>', check:'<path d="m5 12 4 4L19 6"/>', refresh:'<path d="M20 11a8 8 0 1 0 1 4"/><path d="M20 4v7h-7"/>',
    users:'<circle cx="9" cy="8" r="3"/><path d="M3 20v-2a6 6 0 0 1 12 0v2M16 5a3 3 0 0 1 0 6M18 14a5 5 0 0 1 3 4v2"/>', download:'<path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/>',upload:'<path d="M12 15V3m-5 5 5-5 5 5M4 17v4h16v-4"/>',
    'folder-search':'<path d="M10 20H3V5h7l2 3h9v5"/><circle cx="16" cy="17" r="4"/><path d="m19 20 3 3"/>'
  };
  function icon(name) { if (window.SKIcons && !icons[name]) return window.SKIcons.icon(name, 23); return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] || icons.spark}</svg>`; }
  function renderIcons(root = document) { $$("[data-icon]", root).forEach(n => { if (!n.querySelector('svg')) n.innerHTML = icon(n.dataset.icon); }); }
  function getPrefs() { try { return JSON.parse(localStorage.getItem(prefsKey) || '{}'); } catch (_) { return {}; } }
  let prefs = getPrefs(), activeCategory = 'all', query = '', current = null, stepIndex = 0, freeMode = false, poll = 0;
  let touched = false, advancing = false, screen = 'homeScreen', session = 0, events = new Set(), repositionQueued = false, practicedId = null, sessionFinished = false;
  let stepEpoch = 0, prefillReady = false, continueReadyAt = 0, clickShieldUntil = 0, continueTimer = 0;
  const savePrefs = () => { try { localStorage.setItem(prefsKey, JSON.stringify(prefs)); } catch (_) {} };
  const categoryName = {start:'先学基础',rules:'配置规则',advanced:'更多功能'};
  const lesson = id => lessons.find(item => item.id === id) || lessons[0];
  function setScreen(name) {
    screen = name; $$('.screen').forEach(s => { s.hidden = s.id !== name; }); window.scrollTo(0, 0); renderIcons();
    const id = name === 'introScreen' ? 'introPerspective' : name === 'successScreen' && !['import','export'].includes(current?.id) ? 'successPerspective' : null;
    for (const other of ['introPerspective','successPerspective']) if (other !== id) window.GuidePerspective?.destroy($(other));
    if (id && current) {
      const instance = window.GuidePerspective?.mount($(id), current.id, {reducedMotion: document.documentElement.dataset.motion === 'reduce'});
      if (name === 'introScreen') { $('introScene').hidden = !!instance; $('introComparison').hidden = !!instance; }
    }
    syncContinueSurface();
  }
  function demoArt(type, root) {
    if (root.id === 'heroScene') {
      const detail = type === 'kstat' ? '<rect x="89" y="89" width="67" height="34" rx="11" fill="#fff" stroke="#6caa8d"/><text x="122" y="111" text-anchor="middle" font-size="14" font-weight="700" fill="#438364">128 B</text>' : type === 'redirect' ? '<rect x="90" y="88" width="64" height="34" rx="11" fill="#fff" stroke="#c39b68"/><path d="M101 105h35m-7-6 7 6-7 6" fill="none" stroke="#b48349" stroke-width="3"/>' : '<circle cx="131" cy="106" r="23" fill="#fff" stroke="#b39ad9" stroke-width="2"/><g fill="none" stroke="#8063b4" stroke-width="2"><path d="M115 106s6-10 16-10 16 10 16 10-6 10-16 10-16-10-16-10Z"/><circle cx="131" cy="106" r="4"/><path d="m118 92 26 28"/></g>';
      root.innerHTML = `<svg viewBox="0 0 175 170" xmlns="http://www.w3.org/2000/svg"><ellipse cx="94" cy="145" rx="52" ry="8" fill="#e5def1"/><circle cx="88" cy="85" r="66" fill="#eee7fa"/><g class="float-file"><g transform="rotate(-10 85 80)"><rect x="37" y="38" width="80" height="102" rx="14" fill="#e0d6f2"/><rect x="43" y="30" width="81" height="103" rx="14" fill="white" stroke="#bda6dc" stroke-width="2"/><path d="M61 58h44M61 74h31M61 90h39" stroke="#c4b0e4" stroke-width="5" stroke-linecap="round"/></g>${detail}</g><path d="m139 31 3 7 7 3-7 3-3 7-3-7-7-3 7-3 3-7Z" fill="#b49ad7" class="scene-pulse"/><circle cx="28" cy="115" r="4" fill="#c9b3e9" class="scene-pulse"/></svg>`;
      return;
    }
    if (window.GuideScenes) { root.innerHTML = window.GuideScenes.render(type); return; }
    const colors = {path:'#7c67bd',kstat:'#4d9a7b',redirect:'#c28a47'}; const color = colors[type] || colors.path;
    root.innerHTML = `<svg viewBox="0 0 300 180" xmlns="http://www.w3.org/2000/svg"><path d="M25 130 70 78l44 22 45-63 116 81" fill="none" stroke="#c9bee3" stroke-width="2" stroke-dasharray="5 7" class="scene-dash"/><g class="float-file"><rect x="70" y="44" width="86" height="104" rx="13" fill="#fff" stroke="${color}" stroke-width="3"/><path d="M88 70h48M88 88h33M88 106h45" stroke="${color}" stroke-width="4" stroke-linecap="round" opacity=".6"/><circle cx="130" cy="138" r="18" fill="${color}"/><path d="m122 138 6 6 11-13" stroke="white" stroke-width="3" fill="none"/></g><circle cx="239" cy="62" r="9" fill="${color}" class="orbit-dot"/><circle cx="211" cy="126" r="5" fill="#e8bd6c" class="scene-pulse"/></svg>`;
  }
  function renderHome() {
    const bucket = l => l.category === '入门' ? 'start' : l.category === '常用规则' || l.category === '进阶规则' ? 'rules' : 'advanced';
    const filtered = lessons.filter(l => (activeCategory === 'all' || bucket(l) === activeCategory) && (!query || `${l.title} ${l.purpose} ${l.example}`.toLowerCase().includes(query.toLowerCase())));
    $('lessonCount').textContent = `${filtered.length} 个练习`;
    $('lessonGrid').replaceChildren(...filtered.map(l => {
      const button = document.createElement('button'); button.className = 'lesson-card'; button.dataset.lessonId = l.id; button.style.setProperty('--card-color', l.color || '#7460b7'); button.style.setProperty('--card-tint', l.tint || '#eee9fa');
      const done = !!prefs.done?.[l.id]; button.innerHTML = `<span class="lesson-symbol">${icon(l.icon || 'spark')}</span>${done ? '<span class="lesson-status">'+icon('check')+'已完成</span>' : ''}<h3>${escapeHtml(l.title)}</h3><p>${escapeHtml(l.purpose)}</p><footer><span>${escapeHtml(l.categoryLabel || categoryName[l.category] || l.category || '练习')}</span><span>${escapeHtml(l.duration || '3 分钟')} ${icon('arrow')}</span></footer>`;
      button.onclick = () => showIntro(l.id); return button;
    }));
    $('noResults').hidden = filtered.length > 0;
    $('totalProgress').style.width = `${lessons.length ? Math.round(Object.keys(prefs.done || {}).length / lessons.length * 100) : 0}%`;
    const next = lessons.find(l => !prefs.done?.[l.id]) || lessons[0];
    if (next) { $('continueTitle').textContent = prefs.done?.[next.id] ? '再练一次，熟悉得更快' : next.title; $('continueDescription').textContent = prefs.done?.[next.id] ? next.purpose : next.subtitle || next.example; $('continueButton').onclick = () => showIntro(next.id); }
    $$('.category-filters button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.category === activeCategory)));
    $('lessonSearch').value = query; $('clearSearch').hidden = !query;
  }
  function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x])); }
  function showIntro(id) {
    current = lesson(id); $('introCategory').textContent = current.categoryLabel || current.category || '认识功能';
    $('introDuration').textContent = current.duration || ''; $('introEyebrow').textContent = '有什么用 · 能做什么';
    $('introTitle').textContent = current.title; $('introPurpose').textContent = current.purpose;
    $('introBefore').textContent = current.before; $('introAfter').textContent = current.after; $('introExample').textContent = current.example;
    $('introScene').innerHTML = window.GuideScenes?.render(current.id) || current.scene || '';
    const advanced = current.advanced || [];
    $('introAdvancedContent').innerHTML = advanced.map(a => `<h3>${escapeHtml(a.title)}</h3><p>${escapeHtml(a.text)}</p>`).join('');
    $('introAdvanced').open = false;
    $('startLesson').innerHTML = `${practicedId === current.id && !sessionFinished && sim()?.state?.uiReady ? '继续本次练习' : '开始引导练习'} <span data-icon="arrow"></span>`;
    setScreen('introScreen');
  }
  function frameDoc() { const f = $('lessonFrame'); try { return f.contentDocument || f.contentWindow.document; } catch (_) { return null; } }
  function sim() { try { return $('lessonFrame').contentWindow.GuideSimulator; } catch (_) { return null; } }
  function startPractice(id, free = false) {
    current = lesson(id); practicedId = current.id; sessionFinished = false; freeMode = free; stepIndex = 0; session++; touched = false; advancing = false;
    stepEpoch++; prefillReady = false; clickShieldUntil = 0;
    setScreen('practiceScreen'); $('tourTitle').textContent = current.title; $('practiceLoading').hidden = false;
    $('tourMask').hidden = true; $('practiceScreen').classList.toggle('free-mode', freeMode);
    $('lessonFrame').src = `simulator/index.html?lesson=${encodeURIComponent(current.id)}&kernel=${encodeURIComponent(prefs.kernel || '6.12')}&run=${session}`;
    clearInterval(poll); let attempts = 0;
    poll = setInterval(() => {
      if (frameDoc()?.readyState === 'complete' && sim()?.state?.uiReady) {
        $('practiceLoading').hidden = true; clearInterval(poll); bindFrame(); renderStep();
      } else if (++attempts > 200) {
        clearInterval(poll); $('practiceLoading').innerHTML = '<strong>练习桌面还没准备好</strong><span>点右上角菜单，重新开始本课。</span>';
      }
    }, 80);
  }
  function bindFrame() {
    const doc = frameDoc();
    const interacted = e => {
      if (screen !== 'practiceScreen' || !e.isTrusted) return;
      const target = e.target;
      let matches = false;
      try { matches = !!target.closest(currentStep()?.target || 'guide-no-target'); } catch (_) {}
      if (matches) touched = true;
      else if (e.type === 'click' && currentStep()?.target?.includes('.fm-row') && target.closest('.fm-row')) {
        touched = false;
        showToast('选中了别的条目。关闭菜单，再选紫色框中的对象。');
      }
      for (const c of eventConditions(currentStep()?.complete)) {
        try { if (e.type === 'click' && target.closest(c.selector)) events.add(c.selector); } catch (_) {}
      }
    };
    ['pointerdown','click','input','change','contextmenu'].forEach(type => doc.addEventListener(type, interacted, true));
    doc.addEventListener('scroll', queuePosition, true);
    doc.defaultView.addEventListener('resize', queuePosition);
  }
  function eventConditions(c) { if (!c) return []; return c.type === 'event' ? [c] : (c.conditions || []).flatMap(eventConditions); }
  function queuePosition() { if (repositionQueued) return; repositionQueued = true; requestAnimationFrame(() => { repositionQueued = false; renderTarget(false); }); }
  function condition(value) {
    if (!value) return true; const type = value.type;
    if (type === 'all') return (value.conditions || []).every(condition); if (type === 'any') return (value.conditions || []).some(condition); if (type === 'continue') return false;
    const doc = frameDoc(); if (!doc) return false; const node = value.selector ? doc.querySelector(value.selector) : null;
    if (type === 'visible') return !!node && !!(node.offsetWidth || node.offsetHeight || node.getClientRects().length) && !node.hidden;
    if (type === 'hidden') return !node || node.hidden || !(node.offsetWidth || node.offsetHeight || node.getClientRects().length);
    if (type === 'value') { if (!node) return false; return node.type === 'checkbox' ? node.checked === Boolean(value.value) : String(node.value) === String(value.value); }
    if (type === 'text') return !!node && node.textContent.trim() === String(value.equals);
    if (type === 'view') return doc.body.dataset.activeView === value.name || !!doc.querySelector(`[data-view="${value.name}"].show`);
    if (type === 'config' || type === 'applied' || type === 'exported') {
      const source = type === 'applied' ? sim()?.state?.result?.config : type === 'exported' ? sim()?.state?.exported?.config : sim()?.state?.[value.source === 'draft' ? 'config' : value.source || 'config'];
      if (!source) return false;
      if (type === 'applied') return sim()?.state?.result?.result === 'applied' && sim()?.state?.result?.saved === true && sim()?.calls?.some(c => c.route === '/api/susfs/config-save') && (value.expect || []).every(x => objectCondition(source, x));
      return objectCondition(source, value);
    }
    if (type === 'event') return events.has(value.selector);
    return false;
  }
  function objectCondition(obj, spec) { const path = spec.path || ''; const got = path.split('.').filter(Boolean).reduce((v, k) => v == null ? undefined : v[k], obj); if ('equals' in spec) return JSON.stringify(got) === JSON.stringify(spec.equals); if ('contains' in spec) return Array.isArray(got) ? got.some(v => JSON.stringify(v) === JSON.stringify(spec.contains)) : String(got ?? '').includes(String(spec.contains)); return got !== undefined; }
  function currentStep() { return current?.steps?.[stepIndex]; }
  function isReadStep() { const step = currentStep(); return !!step && (step.complete?.type === 'continue' || !!step.prefill); }
  function awaitingContinue() { return screen === 'practiceScreen' && !freeMode && isReadStep() && $('practiceLoading').hidden; }
  function continueReady() {
    return awaitingContinue() && !advancing && prefillReady && performance.now() >= continueReadyAt
      && !$('tourMenu').open && !$('settingsDialog').open;
  }
  function syncContinueSurface() {
    clearTimeout(continueTimer);
    const reading = awaitingContinue(), guard = screen === 'practiceScreen' && performance.now() < clickShieldUntil;
    $('continueLayer').hidden = !(reading || guard);
    $('lessonFrame').inert = reading || guard;
    if (reading || guard) $('lessonFrame').setAttribute('tabindex', '-1'); else $('lessonFrame').removeAttribute('tabindex');
    $('continueLayer').dataset.mode = reading ? 'read' : 'guard';
    $('continueLayer').setAttribute('aria-label', reading ? '阅读提示后轻点任意位置继续' : '正在进入下一步');
    $('tapContinueNotice').hidden = !reading;
    $('coachCard').classList.toggle('read-step', reading);
    if (reading || guard) {
      const delay = Math.max(continueReadyAt, clickShieldUntil) - performance.now();
      if (delay > 0) continueTimer = setTimeout(syncContinueSurface, delay + 10);
    }
  }
  function prefillExample(step, epoch, attempt = 0) {
    if (epoch !== stepEpoch || screen !== 'practiceScreen' || freeMode) return;
    const doc = frameDoc(), field = doc?.querySelector(step.prefill.selector);
    if (!field || field.disabled || !field.getClientRects().length) {
      if (attempt < 30) setTimeout(() => prefillExample(step, epoch, attempt + 1), 50);
      else showToast('示例还没准备好，可从右上角重新开始本课');
      return;
    }
    const win = doc.defaultView;
    const prototype = field.tagName === 'TEXTAREA' ? win.HTMLTextAreaElement.prototype : win.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    if (!setter) return;
    setter.call(field, String(step.prefill.value));
    field.dispatchEvent(new win.Event('input', {bubbles:true}));
    field.dispatchEvent(new win.Event('change', {bubbles:true}));
    prefillReady = condition(step.complete);
    syncContinueSurface();
  }
  function renderStep() {
    const step = currentStep(); if (!step) return finishLesson();
    const epoch = ++stepEpoch; touched = false; advancing = false; events.clear();
    prefillReady = !step.prefill; continueReadyAt = Math.max(performance.now() + 180, clickShieldUntil);
    const total = current.steps.length;
    $('stepNumber').textContent = String(stepIndex + 1).padStart(2, '0'); $('stepCounter').textContent = `${stepIndex + 1} / ${total}`;
    $('stepKicker').textContent = freeMode ? '按自己的节奏试试' : step.prefill ? '示例已准备 · 先看懂这里' : isReadStep() ? '看一下这个提示' : '现在轮到你';
    $('stepTitle').textContent = freeMode ? '自由练习桌面' : step.title;
    $('stepInstruction').textContent = freeMode ? '可以随意配置规则。右上角菜单可重新开始引导，示例不会影响设备。' : step.instruction;
    $('stepWhy').hidden = true; $('stepWhy').textContent = step.why || '';
    $('tourNext').hidden = true; $('stepFeedback').hidden = true;
    $('stepProgress').style.width = `${Math.round(stepIndex / total * 100)}%`;
    if (step.prefill && !freeMode) prefillExample(step, epoch);
    renderTarget(); syncContinueSurface();
    if (freeMode) $('tourMask').hidden = true;
  }
  function renderTarget(scroll = true) {
    const step = currentStep(), target = step?.target, doc = frameDoc(); if (!target || !doc || freeMode || screen !== 'practiceScreen') { $('tourMask').hidden = true; return; } const node = doc.querySelector(target); if (!node) { $('tourMask').hidden = true; return; }
    if (!(node.offsetWidth || node.offsetHeight || node.getClientRects().length)) { $('tourMask').hidden = true; return; }
    if (scroll) try { node.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'auto' }); } catch (_) {}
    requestAnimationFrame(() => { if(step !== currentStep() || screen !== 'practiceScreen') return; const r = node.getBoundingClientRect(), fr = $('lessonFrame').getBoundingClientRect(), canvas = $('practiceCanvas').getBoundingClientRect(); const x = fr.left - canvas.left + r.left, y = fr.top - canvas.top + r.top; const ring = $('targetRing'); ring.style.left = `${Math.max(2, x - 5)}px`; ring.style.top = `${Math.max(2, y - 5)}px`; ring.style.width = `${r.width + 10}px`; ring.style.height = `${r.height + 10}px`; const gesture = $('targetGesture'); gesture.style.left = `${Math.min(canvas.width - 84, Math.max(8, x + r.width - 12))}px`; gesture.style.top = `${Math.max(8, y - 35)}px`; const top = Math.max(0, y - 5), bottom = Math.min(canvas.height, y + r.height + 5); $$('.scrim').forEach(s => { s.style.left = '0'; s.style.right = '0'; }); $('.scrim.top').style.height = `${top}px`; $('.scrim.bottom').style.top = `${bottom}px`; $('.scrim.bottom').style.height = `${Math.max(0, canvas.height - bottom)}px`; $('.scrim.left').style.top = `${top}px`; $('.scrim.left').style.bottom = `${canvas.height - bottom}px`; $('.scrim.left').style.width = `${Math.max(0, x - 5)}px`; $('.scrim.right').style.top = `${top}px`; $('.scrim.right').style.bottom = `${canvas.height - bottom}px`; $('.scrim.right').style.left = `${Math.min(canvas.width, x + r.width + 5)}px`; $('targetGesture').textContent = step.prefill ? '示例已填好' : step.complete?.type === 'continue' ? '看这里' : step.gesture === 'longpress' ? '长按这里' : step.gesture === 'fill' ? '填写这里' : '点这里'; $('tourMask').hidden = false; });
  }
  function checkStep() {
    if (!current || freeMode || !touched || advancing || screen !== 'practiceScreen' || $('tourMenu').open || $('settingsDialog').open) return;
    const step = currentStep(); if (!step || isReadStep()) return;
    if (condition(step.complete)) {
      advancing = true; const token = session, epoch = stepEpoch; $('stepFeedback').hidden = false; $('stepFeedback').innerHTML = `${icon('check')} 做对了`;
      setTimeout(() => { if (epoch !== stepEpoch || session !== token) return; if (screen !== 'practiceScreen' || $('tourMenu').open || !condition(step.complete)) { advancing = false; $('stepFeedback').hidden = true; return; } advance(); }, 420);
    }
  }
  function advance() { if (stepIndex < current.steps.length - 1) { stepIndex++; renderStep(); } else finishLesson(); }
  function acknowledge(event) {
    if (!event?.isTrusted || !continueReady()) return;
    const step = currentStep();
    if (step.prefill && !condition(step.complete)) return;
    event.preventDefault(); event.stopPropagation();
    const epoch = stepEpoch, token = session;
    advancing = true; clickShieldUntil = performance.now() + 560;
    $('stepFeedback').hidden = false; $('stepFeedback').innerHTML = `${icon('arrow')} 继续下一步`;
    syncContinueSurface();
    setTimeout(() => {
      if (epoch !== stepEpoch || token !== session) return;
      if (screen !== 'practiceScreen' || $('tourMenu').open) { advancing = false; $('stepFeedback').hidden = true; syncContinueSurface(); return; }
      advance();
    }, 160);
  }
  function finishLesson() { clearInterval(poll); sessionFinished = true; prefs.done = {...(prefs.done || {}), [current.id]: true}; savePrefs(); $('successTitle').innerHTML = '这项操作，<br>你已经会了。'; $('successDescription').textContent = current.title; $('successOutcome').textContent = current.outcome || current.after; const q = current.challenge || {}; $('quizQuestion').textContent = q.question || '什么时候才算真正提交了规则？'; $('quizExplanation').hidden = true; $('quizChoices').replaceChildren(...(q.choices || ['保存规则','保存并应用']).map((choice, i) => { const b = document.createElement('button'); b.innerHTML = `<span>${String.fromCharCode(65+i)}</span>${escapeHtml(choice)}`; b.onclick = () => { $$('#quizChoices button').forEach(x => x.classList.remove('correct','wrong')); b.classList.add(i === q.answer ? 'correct' : 'wrong'); $('quizExplanation').hidden = false; $('quizExplanation').textContent = i === q.answer ? (q.explanation || '答对了。') : '再想想刚才的操作顺序，再点一次。'; }; return b; })); $('nextLesson').onclick = () => { const next = lessons[(lessons.findIndex(l => l.id === current.id) + 1) % lessons.length]; showIntro(next.id); }; setScreen('successScreen'); }
  function showToast(text) { const t = $('toast'); t.textContent = text; t.hidden = false; clearTimeout(showToast.timer); showToast.timer = setTimeout(() => { t.hidden = true; }, 2400); }
  function wire() {
    document.documentElement.dataset.motion = prefs.motion || (matchMedia('(prefers-reduced-motion: reduce)').matches ? 'reduce' : 'full');
    renderIcons(); demoArt('path', $('heroScene')); $$('.hero-switch button').forEach(b => b.onclick = () => { $$('.hero-switch button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); const captions = {path:'让指定应用看不到你选中的文件或目录。',kstat:'只替换应用看到的文件属性，原文件内容不变。',redirect:'打开 A 时返回 B 的内容；访问权限仍按当前支持范围判断。'}; $('heroCaption').textContent = captions[b.dataset.demo]; demoArt(b.dataset.demo, $('heroScene')); });
    $('lessonSearch').oninput = e => { query = e.target.value; renderHome(); }; $('clearSearch').onclick = () => { query = ''; renderHome(); }; $$('.category-filters button').forEach(b => b.onclick = () => { activeCategory = b.dataset.category; renderHome(); });
    $('settingsButton').onclick = () => { $('reduceMotion').checked = document.documentElement.dataset.motion === 'reduce'; $('kernelSelect').value = prefs.kernel || '6.12'; $('settingsDialog').showModal(); };
    $('reduceMotion').onchange = e => { document.documentElement.dataset.motion = e.target.checked ? 'reduce' : 'full'; prefs.motion = e.target.checked ? 'reduce' : 'full'; savePrefs(); };
    $('kernelSelect').onchange = e => {
      prefs.kernel = e.target.value; savePrefs();
      if (practicedId) { practicedId = null; clearInterval(poll); $('lessonFrame').src = 'about:blank'; }
      showToast('练习内核已切换，下次进入会重新准备示例');
    };
    $('resetProgress').onclick = () => { prefs.done = {}; savePrefs(); renderHome(); $('settingsDialog').close(); showToast('学习记录已清除'); };
    $('nativeSettings').hidden = !window.GuideApp;
    $('nativeSettings').onclick = () => { try { window.GuideApp?.showReadingSettings?.(); } catch (_) {} };
    $('openReference').onclick = () => { if (!$('referenceFrame').getAttribute('src')) $('referenceFrame').src = 'reference/index.html'; setScreen('referenceScreen'); };
    $('referenceBack').onclick = home;
    $$('[data-home]').forEach(b => b.onclick = home);
    $('startLesson').onclick = () => {
      if (practicedId === current.id && !sessionFinished && sim()?.state?.uiReady) { setScreen('practiceScreen'); renderStep(); }
      else startPractice(current.id);
    };
    $('freePractice').onclick = () => startPractice(current.id, true);
    $('continueLayer').onpointerdown = e => e.preventDefault();
    $('continueLayer').onclick = acknowledge;
    $('tapContinueNotice').onclick = acknowledge;
    $('tourNext').onclick = acknowledge;
    $('practiceScreen').addEventListener('click', e => {
      if (e.target.closest('button,a,input,textarea,select,summary,dialog,[role="button"]')) return;
      acknowledge(e);
    });
    $('tourHint').onclick = () => { $('stepWhy').hidden = !$('stepWhy').hidden; queuePosition(); };
    $('tourLocate').onclick = () => { if (freeMode) { showToast('自由练习中，可用右上角菜单重新开始引导'); return; } renderTarget(); showToast('紫色呼吸框就是下一步要操作的位置'); };
    $('tourHome').onclick = () => $('tourMenu').showModal();
    $('tourMore').onclick = () => { $('toggleGuidance').textContent = freeMode ? '重新开始引导练习' : '切换到自由练习'; $('tourMenu').showModal(); };
    $('exitLesson').onclick = () => { $('tourMenu').close(); home(); };
    $('reviewIntro').onclick = () => { $('tourMenu').close(); showIntro(current.id); };
    $('restartLesson').onclick = () => { $('tourMenu').close(); startPractice(current.id, false); };
    $('toggleGuidance').onclick = () => { $('tourMenu').close(); if (freeMode) startPractice(current.id, false); else { freeMode = true; $('practiceScreen').classList.add('free-mode'); renderStep(); } };
    $('tourRetry').onclick = () => startPractice(current.id, false);
    window.addEventListener('resize', queuePosition);
    new ResizeObserver(queuePosition).observe($('practiceCanvas'));
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') savePrefs(); });
    setScreen('homeScreen'); renderHome();
    setInterval(checkStep, 220);
  }
  function home() { for (const id of ['tourMenu','settingsDialog']) if ($(id).open) $(id).close(); setScreen('homeScreen'); renderHome(); }
  function back() {
    for (const id of ['tourMenu','settingsDialog']) if ($(id).open) { $(id).close(); return true; }
    if (screen === 'referenceScreen') { try { if ($('referenceFrame').contentWindow.GuideAndroid?.back?.()) return true; } catch (_) {} home(); return true; }
    if (screen === 'practiceScreen') { $('tourMenu').showModal(); return true; }
    if (screen !== 'homeScreen') { home(); return true; }
    if (query) { query = ''; renderHome(); return true; }
    return false;
  }
  window.GuideAndroid = {
    back, persist:savePrefs, cover:home,
    print: () => { $('referenceFrame').src = 'reference/index.html'; setScreen('referenceScreen'); showToast('打开图文参考后，点“打印 / 存为 PDF”'); }
  };
  window.TutorialApp = { getState: () => ({lessonId: current?.id || null, stepIndex, completed: screen === 'successScreen', screen, freeMode, awaitingContinue:awaitingContinue(), continueReady:continueReady()}), icon };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire, {once:true}); else wire();
})();
