let toastTimer = null;

function showToast(message) {
	const toast = document.getElementById("toast");
	if (!toast) return;

	toast.textContent = message;
	toast.classList.add("show");

	// 清理之前的定时器
	if (toastTimer) {
		clearTimeout(toastTimer);
	}

	toastTimer = setTimeout(() => {
		toast.classList.remove("show");
	}, 1800);
}
