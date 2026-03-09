// ====== DOM ======
const $verSpan = document.getElementById('module-version');

const $autoThirdAppToggle = document.getElementById("toggle-auto-third-app");
const $fixTeeToggle = document.getElementById("toggle-fix-tee");
const $hideBootloaderToggle = document.getElementById("toggle-hide-bl");

const $targetEditor = document.getElementById("target-editor");
const $btnCopyTarget = document.getElementById("btn-copy-target");
const $btnPasteTarget = document.getElementById("btn-paste-target");
const $btnSaveTarget = document.getElementById("btn-save-target");

const $keyboxEditor = document.getElementById("keybox-editor");
const $btnCopyKeybox = document.getElementById("btn-copy-keybox");
const $btnPasteKeybox = document.getElementById("btn-paste-keybox");
const $btnSaveKeybox = document.getElementById("btn-save-keybox");
	
const $bootloaderScriptEditor = document.getElementById("bl-script-editor");
const $btnDebug = document.getElementById('btn-debug-props');

const $btnCopyBootloader = document.getElementById("btn-copy-bl");
const $btnPasteBootloader = document.getElementById("btn-paste-bl");
const $btnSaveBootloader = document.getElementById("btn-save-bl");

async function loadSettings() {
	try {
		$autoThirdAppToggle.checked = (await RequestApi.getAutoThirdAppToggle()) == "1";
		$fixTeeToggle.checked = (await RequestApi.getFixTeeToggle()) == "1";
		$hideBootloaderToggle.checked = (await RequestApi.getHideBootloaderToggle()) == "1";

	} catch (err) {
		console.error('读取配置失败:', err);
		alert('读取配置失败：' + (err instanceof Error ? err.message : String(err)));
	}
}

async function saveSettings() {
	try {
		if ((await RequestApi.setAutoThirdAppToggle($autoThirdAppToggle.checked ? "1" : "0")) !== 'OK') throw new Error(result);
		if ((await RequestApi.setFixTeeToggle($fixTeeToggle.checked ? "1" : "0")) !== 'OK') throw new Error(result);
		if ((await RequestApi.setHideBootloaderToggle($hideBootloaderToggle.checked ? "1" : "0")) !== 'OK') throw new Error(result);
		
		showToast("设置成功，重启生效");
		return true;
	} catch (err) {
		console.error('保存配置失败:', err);
		alert('保存失败：' + (err instanceof Error ? err.message : String(err)));
	}
}

async function loadTargetTxt() {
	try {
		$targetEditor.value = await RequestApi.getTargetTxt();
	} catch (err) {
		console.error('读取target.txt失败:', err);
		alert('读取target.txt失败：' + (err instanceof Error ? err.message : String(err)));
	}
}

async function saveTargetTxt() {
	try {
		const result = await RequestApi.setTargetTxt($targetEditor.value);
		if (result !== 'OK') {
			alert('保存失败：' + result);
			return false;
		}
		showToast("已保存，重启生效");
		return true;
	} catch (err) {
		console.error('保存target.txt失败:', err);
		alert('保存target.txt失败：' + (err instanceof Error ? err.message : String(err)));
		return false;
	}
}

async function loadKeyboxXml() {
	try {
		$keyboxEditor.value = await RequestApi.getKeyboxXml();
	} catch (err) {
		console.error('读取keybox.xml失败:', err);
		alert('读取keybox.xml失败：' + (err instanceof Error ? err.message : String(err)));
	}
}

async function saveKeyboxXml() {
	try {
		const result = await RequestApi.setKeyboxXml($keyboxEditor.value);
		if (result !== 'OK') {
			alert('保存失败：' + result);
			return false;
		}
		showToast("已保存，重启生效");
		return true;
	} catch (err) {
		console.error('保存keybox.xml失败:', err);
		alert('保存keybox.xml失败：' + (err instanceof Error ? err.message : String(err)));
		return false;
	}
}

async function loadBootloaderScript() {
	try {
		$bootloaderScriptEditor.value = await RequestApi.getBootloaderScript();
	} catch (err) {
		console.error('读取脚本失败:', err);
		alert('读取脚本失败：' + (err instanceof Error ? err.message : String(err)));
	}
}

async function saveBootloaderScript() {
	try {
		const result = await RequestApi.setBootloaderScript($bootloaderScriptEditor.value);
		if (result !== 'OK') {
			alert('保存失败：' + result);
			return false;
		}
		showToast("已保存，重启生效");
		return true;
	} catch (err) {
		console.error('保存脚本失败:', err);
		alert('保存脚本失败：' + (err instanceof Error ? err.message : String(err)));
		return false;
	}
}

async function showAllPropsModal() {
	const modal = document.getElementById('debug-modal');
	const btnCloseModal = document.getElementById('btn-close-modal');
	const btnCopyDebug = document.getElementById('btn-copy-debug');
	const debugOutput = document.getElementById('debug-output');

    debugOutput.value = "正在读取系统属性 (Running getprop)...";
	modal.classList.remove('hidden');
	
	const closeModal = () => {
        modal.classList.add('hidden');
    };
    btnCloseModal.addEventListener('click', closeModal);
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });

    btnCopyDebug.addEventListener('click', () => {
        copyToClipboard(debugOutput.value);
		showToast("已复制");
    });

   try {
		debugOutput.value = await RequestApi.getAllProps();
	} catch (err) {
		debugOutput.value = "获取属性失败:\n" + (err instanceof Error ? err.message : String(err));
	}
}

function copyToClipboard(text) {
	let tempTextarea = document.createElement('textarea');
	document.body.appendChild(tempTextarea);
	tempTextarea.value = text;
	tempTextarea.select();
	document.execCommand('copy');
	document.body.removeChild(tempTextarea);
}

async function readClipboardText() {
  try {
    if (!navigator.clipboard || !navigator.clipboard.readText) return null;
    // 很多环境需要安全上下文
    if (!window.isSecureContext) return null;
    return await navigator.clipboard.readText();
  } catch (e) {
    console.error("readClipboardText failed:", e);
    return null;
  }
}

function render() {
	$autoThirdAppToggle.addEventListener("change", async function () {
		const ok = await saveSettings();
		if(ok) loadTargetTxt();
	});

	$fixTeeToggle.addEventListener("change", async function () {
		await saveSettings();
	});
	
	$hideBootloaderToggle.addEventListener("change", async function () {
		await saveSettings();
	});
	
	$btnCopyTarget.addEventListener("click", function () {
		copyToClipboard($targetEditor.value);
		showToast("已复制");
	});
	
	$btnPasteTarget.addEventListener("click", async () => {
	  const text = await readClipboardText();
	  if (typeof text === "string" && text.length) {
		if (!confirm("将剪贴板内容覆盖全文？")) return;
		$targetEditor.value = text;
	  } else {
		alert("当前浏览器限制，无法读取剪贴板，请长按文本框手动粘贴。");
		$targetEditor.focus();
	  }
	});
	
	$btnSaveTarget.addEventListener("click", async function () {
		await saveTargetTxt();
	});

	$btnCopyKeybox.addEventListener("click", async function () {
		copyToClipboard($keyboxEditor.value);
		showToast("已复制");
	});
	
	$btnPasteKeybox.addEventListener("click", async () => {
	  const text = await readClipboardText();
	  if (typeof text === "string" && text.length) {
		if (!confirm("将剪贴板内容覆盖全文？")) return;
		$keyboxEditor.value = text;
	  } else {
		alert("当前浏览器限制，无法读取剪贴板，请长按文本框手动粘贴。");
		$keyboxEditor.focus();
	  }
	});
	
	$btnSaveKeybox.addEventListener("click", async function () {
		await saveKeyboxXml();
	});
	
	$btnCopyBootloader.addEventListener("click", async function () {
		copyToClipboard($bootloaderScriptEditor.value);
		showToast("已复制");
	});
	
	$btnPasteBootloader.addEventListener("click", async () => {
	  const text = await readClipboardText();
	  if (typeof text === "string" && text.length) {
		if (!confirm("将剪贴板内容覆盖全文？")) return;
		$bootloaderScriptEditor.value = text;
	  } else {
		alert("当前浏览器限制，无法读取剪贴板，请长按文本框手动粘贴。");
		$bootloaderScriptEditor.focus();
	  }
	});
	
	$btnSaveBootloader.addEventListener("click", async function () {
		await saveBootloaderScript();
	});
	
	$btnDebug.addEventListener('click', async () => {
        showAllPropsModal();
    });
}

async function initVersion() {
	try {
		const ver = await RequestApi.getVersion();
		$verSpan.textContent = ver || '未知';
	} catch (err) {
		$verSpan.textContent = '读取失败';
		console.error('getVersion 出错:', err);
		alert('读取版本失败：' + (err instanceof Error ? err.message : String(err)));
	}
}

// ====== 入口初始化 ======
async function onReady() {
	await initVersion();
	await loadSettings();
	await loadTargetTxt();
	await loadKeyboxXml();
	await loadBootloaderScript();
	render();
}
document.addEventListener('DOMContentLoaded', onReady);