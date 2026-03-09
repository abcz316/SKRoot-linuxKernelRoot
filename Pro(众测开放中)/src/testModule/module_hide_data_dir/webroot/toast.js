let toastTimer = null;

/**
 * 居中小提示
 * @param {string} msg 提示文字
 * @param {'success' | 'danger'} type 提示类型
 */
function showToast(msg, type = 'success') {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.className = 'toast';
    document.body.appendChild(toast);
  }

  toast.textContent = msg;

  // 先清掉旧的 class
  toast.classList.remove('toast--success', 'toast--danger', 'toast--show');

  if (type === 'danger') {
    toast.classList.add('toast--danger');
  } else {
    toast.classList.add('toast--success');
  }

  // 触发重绘（让重新加 show 时动画生效）
  void toast.offsetWidth;

  toast.classList.add('toast--show');

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('toast--show');
  }, 2000); // 2000 秒自动消失
}
