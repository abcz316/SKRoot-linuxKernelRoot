// ====== 业务配置 ======
const RULE_TYPE = Object.freeze({
  NAME: 'name',
  PATH: 'path'
});

const FORBIDDEN_KEYWORDS = ['system', 'vendor', 'data', 'app'];
const NAME_RULE = /^[A-Za-z0-9._\-+]+$/;
const PATH_SEGMENT_RULE = /^[A-Za-z0-9._\-+]+$/;

// ====== DOM ======
const $list = document.getElementById('list');
const $ruleCount = document.getElementById('ruleCount');
const $btnOpenAdd = document.getElementById('btnOpenAdd');
const $sheetLayer = document.getElementById('sheetLayer');
const $sheetBackdrop = document.getElementById('sheetBackdrop');
const $btnCloseSheet = document.getElementById('btnCloseSheet');
const $modeButtons = Array.from(document.querySelectorAll('.mode-option'));
const $inputLabel = document.getElementById('inputLabel');
const $ruleInput = document.getElementById('ruleInput');
const $btnClearInput = document.getElementById('btnClearInput');
const $error = document.getElementById('error');
const $fieldNote = document.getElementById('fieldNote');
const $btnConfirmAdd = document.getElementById('btnConfirmAdd');

// ====== 状态 ======
/** @type {{type: 'name' | 'path', value: string}[]} */
let items = [];
/** @type {'name' | 'path'} */
let currentMode = RULE_TYPE.NAME;
let isSaving = false;
let lastFocusedElement = null;

// ====== 工具 ======
function showError(message) {
  $error.textContent = message;
  $error.classList.add('show');
  clearTimeout(showError.timer);
  showError.timer = setTimeout(clearError, 3000);
}

function clearError() {
  clearTimeout(showError.timer);
  $error.textContent = '';
  $error.classList.remove('show');
}

function setSaving(saving) {
  isSaving = saving;
  $btnConfirmAdd.disabled = saving;
  $btnConfirmAdd.textContent = saving ? '正在保存…' : '添加';
}

async function save(nextItems = items) {
  try {
    const result = await RequestApi.setHiddenDirsJson(JSON.stringify(nextItems));
    if (result !== 'OK') {
      alert('保存失败：' + result);
      return false;
    }
    return true;
  } catch (err) {
    console.error('保存配置失败:', err);
    alert('保存失败：' + (err instanceof Error ? err.message : String(err)));
    return false;
  }
}

async function load() {
  try {
    const raw = await RequestApi.getHiddenDirsJson();
    if (!raw) return [];

    const data = JSON.parse(raw);
    if (!Array.isArray(data)) {
      throw new Error('配置格式不是数组');
    }

    return data.filter(rule =>
      rule &&
      (rule.type === RULE_TYPE.NAME || rule.type === RULE_TYPE.PATH) &&
      typeof rule.value === 'string' &&
      rule.value.length > 0
    );
  } catch (err) {
    console.error('读取配置失败:', err);
    alert('读取配置失败：' + (err instanceof Error ? err.message : String(err)));
    return [];
  }
}

function containsForbiddenKeyword(value) {
  const lower = value.toLowerCase();
  return FORBIDDEN_KEYWORDS.find(keyword => lower.includes(keyword)) || null;
}

function sanitizeName(raw) {
  const value = (raw || '').trim();

  if (!value) return { error: '目录名称不能为空' };
  if (value.length > 80) return { error: '目录名称不能超过 80 个字符' };
  if (!NAME_RULE.test(value)) {
    return { error: '只允许字母、数字、点、下划线、短横线和加号，不能包含 /' };
  }

  const forbidden = containsForbiddenKeyword(value);
  if (forbidden) {
    return { error: `不能包含系统关键字：${forbidden}` };
  }

  return { value };
}

function normalizePath(raw) {
  let value = (raw || '').trim();
  value = value.replace(/\\/g, '/');
  value = value.replace(/\/{2,}/g, '/');
  if (value.length > 1) value = value.replace(/\/+$/, '');
  return value;
}

function sanitizePath(raw) {
  const value = normalizePath(raw);

  if (!value) return { error: '完整路径不能为空' };
  if (value.length > 512) return { error: '完整路径不能超过 512 个字符' };
  if (!value.startsWith('/data/')) {
    return { error: '路径必须以 /data/ 开头' };
  }

  const relativePath = value.slice('/data/'.length);
  if (!relativePath) return { error: '不能隐藏 /data 根目录' };

  const segments = relativePath.split('/');
  if (segments.some(segment => !segment)) {
    return { error: '路径中不能包含空目录层级' };
  }

  if (segments.some(segment => segment === '.' || segment === '..')) {
    return { error: '路径不能包含 . 或 ..' };
  }

  if (segments.some(segment => !PATH_SEGMENT_RULE.test(segment))) {
    return { error: '路径只允许字母、数字、斜杠、点、下划线、短横线和加号' };
  }

  const forbidden = segments
    .map(segment => containsForbiddenKeyword(segment))
    .find(Boolean);
  if (forbidden) {
    return { error: `路径不能包含系统关键字：${forbidden}` };
  }

  return { value };
}

function sanitizeCurrentInput() {
  return currentMode === RULE_TYPE.NAME
    ? sanitizeName($ruleInput.value)
    : sanitizePath($ruleInput.value);
}

function exists(rule) {
  return items.some(item => item.type === rule.type && item.value === rule.value);
}

function describeRule(rule) {
  return rule.type === RULE_TYPE.NAME
    ? '同名目录批量隐藏'
    : '完整路径精准隐藏';
}

function createElement(tagName, className, text) {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

// ====== 列表渲染 ======
function render() {
  $list.innerHTML = '';
  $ruleCount.textContent = `${items.length} 条`;

  if (!items.length) {
    const empty = createElement('div', 'empty-state');
    empty.innerHTML = `
      <div class="empty-icon" aria-hidden="true">
        <span></span><span></span><span></span>
      </div>
      <div class="empty-title">还没有添加目录</div>
      <div class="empty-desc">点击下方按钮，添加需要隐藏的目录</div>
    `;
    $list.appendChild(empty);
    return;
  }

  items.forEach((rule, index) => {
    const card = createElement('article', 'rule-card');

    const header = createElement('div', 'rule-header');
    const typeBadge = createElement(
      'span',
      `rule-type rule-type--${rule.type}`,
      rule.type === RULE_TYPE.NAME ? '按名称' : '按路径'
    );

    const del = createElement('button', 'rule-delete', '删除');
    del.type = 'button';
    del.setAttribute('aria-label', `删除规则 ${rule.value}`);
    del.addEventListener('click', () => deleteRule(index, del));

    header.append(typeBadge, del);

    const value = createElement('div', 'rule-value', rule.value);
    const description = createElement('div', 'rule-desc', describeRule(rule));

    card.append(header, value, description);
    $list.appendChild(card);
  });
}

async function deleteRule(index, button) {
  if (isSaving) return;

  const nextItems = items.filter((_, itemIndex) => itemIndex !== index);
  button.disabled = true;

  const ok = await save(nextItems);
  button.disabled = false;

  if (!ok) return;

  items = nextItems;
  render();
  showToast('删除成功，重启生效', 'danger');
}

// ====== Bottom Sheet ======
function setMode(mode) {
  currentMode = mode;
  clearError();
  $ruleInput.value = '';

  $modeButtons.forEach(button => {
    const active = button.dataset.mode === mode;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  });

  if (mode === RULE_TYPE.NAME) {
    $inputLabel.textContent = '目录名称';
    $ruleInput.placeholder = '例如：local123';
    $ruleInput.maxLength = 80;
    $fieldNote.textContent = '作用范围：/data 下所有同名目录';
  } else {
    $inputLabel.textContent = '完整路径';
    $ruleInput.placeholder = '例如：/data/aaa/bbb';
    $ruleInput.maxLength = 512;
    $fieldNote.textContent = '作用范围：指定的完整路径';
  }

  updateClearButton();
}

function handleInput() {
  updateClearButton();
  if ($error.classList.contains('show')) clearError();
}

function updateClearButton() {
  $btnClearInput.classList.toggle('visible', $ruleInput.value.length > 0);
}

function openSheet() {
  lastFocusedElement = document.activeElement;
  setMode(RULE_TYPE.NAME);
  $sheetLayer.classList.add('show');
  $sheetLayer.setAttribute('aria-hidden', 'false');
  document.body.classList.add('sheet-open');
}

function closeSheet() {
  if (!$sheetLayer.classList.contains('show') || isSaving) return;

  $sheetLayer.classList.remove('show');
  $sheetLayer.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('sheet-open');
  $ruleInput.blur();
  clearError();

  if (lastFocusedElement instanceof HTMLElement) {
    setTimeout(() => lastFocusedElement.focus(), 180);
  }
}

async function addRule() {
  if (isSaving) return;

  const result = sanitizeCurrentInput();
  if (result.error) {
    showError(result.error);
    return;
  }

  const rule = { type: currentMode, value: result.value };
  if (exists(rule)) {
    showError('这个目录已经添加过了');
    return;
  }

  // 完整路径模式：目录必须真实存在才允许添加
  if (rule.type === RULE_TYPE.PATH) {
    isSaving = true;
    $btnConfirmAdd.disabled = true;
    try {
      const fileExist = await RequestApi.checkFileExist(rule.value);
      if (fileExist !== 'true') {
        isSaving = false;
        $btnConfirmAdd.disabled = false;
        showToast('目录不存在，无法添加', 'danger');
        return;
      }
    } catch (err) {
      isSaving = false;
      $btnConfirmAdd.disabled = false;
      showToast('检查目录失败', 'danger');
      return;
    }

    isSaving = false;
    $btnConfirmAdd.disabled = false;
  }

  const nextItems = [...items, rule];

  setSaving(true);
  const ok = await save(nextItems);
  setSaving(false);

  if (!ok) return;

  items = nextItems;
  render();
  closeSheet();
  showToast('新增成功，重启生效', 'success');
}

// ====== 事件 ======
$btnOpenAdd.addEventListener('click', openSheet);
$sheetBackdrop.addEventListener('click', closeSheet);
$btnCloseSheet.addEventListener('click', closeSheet);
$btnConfirmAdd.addEventListener('click', addRule);

$modeButtons.forEach(button => {
  button.addEventListener('click', () => setMode(button.dataset.mode));
});

$ruleInput.addEventListener('input', handleInput);
$ruleInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') addRule();
});

$btnClearInput.addEventListener('click', () => {
  $ruleInput.value = '';
  handleInput();
  $ruleInput.focus();
});

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeSheet();
});

// ====== 入口初始化 ======
async function onReady() {
  items = await load();
  render();
}

document.addEventListener('DOMContentLoaded', onReady);
