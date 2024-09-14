#ifndef _ROOT_SERVER_H_
#define _ROOT_SERVER_H_
#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

namespace {
const int PORT = 33445;
const char *POST_KEY = "9c5a503d973f104fc607aaf7f61ddb2cbc7af6fde95fc0e9";
const char *SU_BASE_PATH = "/data/local/tmp";

const char* HTML_CONTENT = R"***(
<!DOCTYPE html>
<html lang="zh-CN">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SKRoot Implanted Web Server</title>
    <style>
		:root {
            --purple-200: #BB86FC;
            --purple-500: #6200EE;
            --purple-700: #3700B3;
        }

        body {
            padding: 0px;
        }
		
		h2 {
			margin: 0;
			padding: 4px 0;
			font-size: 20px;
		}
		
		.head-tip {
			font-size: 16px;
			font-weight:bold;
		}
		
		.desc-tip {
			margin-top: 10px;
			font-size:12px;
		}
		
		.warning-tip {
			color: #ff0000;
			margin-top: 10px;
			font-size:13px;
		}
		
		.first-part {
			display: flex;
			flex-direction: column;
		}
		
        .divider {
            width: 100%;
            height: 2px;
            background-color: #ff00ff;
			margin-top: 10px;
        }
		
		.second-part {
			display: flex;
		}
		
		.menu-list {
			display: flex;
			flex-direction: column;
			margin-top: 4px;
			margin-bottom: 10px;
		}
		
		.menu-head-text {
			font-size:12px;
		}
		
		.vertical {
			display: flex;
			margin-left: 4px;
			margin-right: 4px;
			height: 100%;
			width: 2px;
			background-color: #ff00ff;
		}
		
		.output-list {
			display: flex;
			flex-direction: column;
			width: 100%;
			margin-top: 4px;
			margin-bottom: 10px;
		}
		
		.output-tool-list {
			display: flex;
		}
		
        .console {
            border: 1px solid #ddd;
            padding: 2px;
			min-height: 90%;
			width:100%
            overflow-y: hidden;
			resize: none;
			margin-top: 0px;
			margin-left: 0px;
			font-size: 10px;
			border-radius: 2px;
        }

        .btn,.small-btn {
            display: inline-block;
            padding: 5px 15px;
            margin-left:0px;
            border: none;
            background-color: var(--purple-500);
            color: white;
            cursor: hand;
			width:150px;
			height:50px;
			border-radius: 5px;
			box-shadow: 0 3px 6px rgba(0, 0, 0, 0.16), 0 3px 6px rgba(0, 0, 0, 0.23);
        }

        .btn {
            text-align: left;
			margin-bottom:10px;
        }
		
		.btn:active, .small-btn:active {
			box-shadow: 0 2px 4px rgba(0, 0, 0, 0.16), 0 2px 3px rgba(0, 0, 0, 0.23);
			transform: translateY(1px);
		}
		
		.small-btn {
			margin-left:4px;
			margin-bottom:6px;
			width:60px;
			height:30px;
        }

		.modal {
			display: none; 
			position: fixed; 
			z-index: 1; 
			left: 0;
			top: 0;
			width: 100%; 
			height: 100%; 
			overflow: auto; 
			background-color: rgb(0,0,0); 
			background-color: rgba(0,0,0,0.4); 
		}
		.modal-content {
			background-color: #fefefe;
			margin: 15% auto; 
			padding: 10px;
			border: 1px solid #888;
			border-radius: 10px;
			width: 80%; 
		}
		.close {
			margin-top: -5px;
		}

		.close, .clear-input {
			color: #aaa;
			float: right;
			font-size: 28px;
			font-weight: bold;
			cursor: pointer;
		}
		.close:hover,
		.close:focus,
		.clear-input:hover {
			color: black;
			text-decoration: none;
		}
		.filter-input-container {
			position: relative;
			width: 100%;
		}
		.filter-input {
			width: 100%;
			padding: 10px;
			margin-top: 10px;
			margin-bottom: 0px;
			border: 1px solid #ddd;
			box-sizing: border-box;
		}
		.clear-input {
			position: absolute;
			right: 10px;
			top: 5px;
			display: none;
		}
	
		.checkbox-container {
			margin-top: 10px;
			margin-bottom: 10px;
		}

		.checkbox-container input[type="checkbox"] {
			margin-right: 2px;
		}

		.checkbox-container label {
			margin-right: 5px;
		}

		.list-items {
			background-color: #f0f0f0;
			overflow-y: auto;
			max-height: 100%; 
			padding: 0px;
		}
		.list-item {
			padding: 10px;
			margin: 5px 0;
		}
		.list-item:active {
			background-color: #ddd;
		}
		
		.loading-indicator {
			display: none;
			justify-content: center;
			align-items: center;
			position: fixed;
			left: 0;
			top: 0;
			width: 100%;
			height: 100%;
			background-color: rgba(0, 0, 0, 0.5);
			z-index: 1000;
		}

		.loading-box {
			display: flex;
			flex-direction: column;
			align-items: center;
			background-color: #fff;
			padding: 20px;
			border-radius: 10px;
			box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
		}

		.loading-logo {
			width: 40px;
			height: 40px;
			border: 5px solid #f3f3f3;
			border-top: 5px solid #3498db;
			border-radius: 50%;
			animation: spin 2s linear infinite;
		}

		.loading-content {
			margin-top: 20px;
		}

		@keyframes spin {
			from {transform: rotate(0deg);}
			to {transform: rotate(360deg);}
		}
    </style>

    <script>
		let g_lastSuFullPath = '';
		const g_userName = generateRandomString(32);
		function generateRandomString(length) {
			let result = '';
			let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
			let charactersLength = characters.length;
			for (let i = 0; i < length; i++) {
				result += characters.charAt(Math.floor(Math.random() * charactersLength));
			}
			return result;
		}
		function heartbeat() {
			let jsonData = {
				type: 'heartbeat',
			};
			sendJsonToServer(jsonData);
		}
		
		function initAppListModal() {
			var modal = document.getElementById("myAppListModal");
			var span = document.getElementById("myAppListClose");
			var filterInput = document.getElementById('filterAppInput');
			var clearInput = document.getElementById('myAppListClear');
			var listItems = document.getElementById('listAppItems');
			
			span.onclick = function() {
				modal.style.display = "none";
			}

			window.onclick = function(event) {
				if (event.target == modal) {
					modal.style.display = "none";
				}
			}

			filterInput.oninput = function() {
				var filterValue = this.value.toLowerCase();
				var items = listItems.getElementsByClassName('list-item');
				for(var i = 0; i < items.length; i++) {
					var item = items[i];
					if(item.innerHTML.toLowerCase().indexOf(filterValue) > -1) {
						item.style.display = "";
					} else {
						item.style.display = "none";
					}
				}
				if (filterValue) {
					clearInput.style.display = 'block';
					filterInput.style.width = 'calc(100% - 40px)';
				} else {
					clearInput.style.display = 'none';
					filterInput.style.width = '100%';
				}
			}

			clearInput.onclick = function() {
				filterInput.value = '';
				filterInput.dispatchEvent(new Event('input'));
			}


		}
		
		function initFileListModal() {
			var modal = document.getElementById("myFileListModal");
			var span = document.getElementById("myFileListClose");
			var filterInput = document.getElementById('filterFileInput');
			var clearInput = document.getElementById('myFileListClear');
			var listItems = document.getElementById('listFileItems');
			span.onclick = function() {
				modal.style.display = "none";
			}
			window.onclick = function(event) {
				if (event.target == modal) {
					modal.style.display = "none";
				}
			}

			filterInput.oninput = function() {
				var filterValue = this.value.toLowerCase();
				var items = listItems.getElementsByClassName('list-item');
				for(var i = 0; i < items.length; i++) {
					var item = items[i];
					if(item.innerHTML.toLowerCase().indexOf(filterValue) > -1) {
						item.style.display = "";
					} else {
						item.style.display = "none";
					}
				}
				if (filterValue) {
					clearInput.style.display = 'block';
					filterInput.style.width = 'calc(100% - 40px)';
				} else {
					clearInput.style.display = 'none';
					filterInput.style.width = '100%';
				}
			}

			clearInput.onclick = function() {
				filterInput.value = '';
				filterInput.dispatchEvent(new Event('input'));
			}
		}

		window.onload = function () {
			setInterval(heartbeat, 500);
			initAppListModal();
			initFileListModal();
		};

		function copyToClipboard(text) {
			let tempTextarea = document.createElement('textarea');
			document.body.appendChild(tempTextarea);
			tempTextarea.value = text;
			tempTextarea.select();
			document.execCommand('copy');
			document.body.removeChild(tempTextarea);
		}

		function showLoadingIndicator(text) {
			var loadingIndicator = document.getElementById('loadingIndicator');
			var loadingText = document.getElementById('loadingText');
			loadingText.innerHTML = text;
			loadingIndicator.style.display = 'flex';
		}

		function hideLoadingIndicator(isShow) {
			var loadingIndicator = document.getElementById('loadingIndicator');
			var loadingText = document.getElementById('loadingText');
			loadingText.innerHTML = '';
			loadingIndicator.style.display = 'none';
		}
		
		function sendJsonToServer(jsonData) {
			jsonData.userName = g_userName;
			return new Promise((resolve, reject) => {
				fetch('http://127.0.0.1:11945efd3337ff4cd1168d98bc108cae/6a181c88b7d5b51ff84fb344acbcee86', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					body: JSON.stringify(jsonData)
				})
				.then(response => response.json())
				.then(data => {
					//console.log(data);
					resolve(data);
				})
				.catch(error => {
					//console.error('Error:', error);
					reject(error);
				});
			});
		}

		function appendConsole(txt) {
			if(!txt || !txt.length) { return; }
			let consoleText = document.getElementById('console');
			consoleText.value += txt;
			consoleText.value += '\n\n';
			consoleText.scrollTop = consoleText.scrollHeight;
		}

		function testRootBtnClick() {
			let jsonData = {
				type: 'testRoot',
			};
			sendJsonToServer(jsonData)
			.then(data => {
				appendConsole(data.content);
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}

        function runRootCmdBtnClick() {
			var shell = prompt("请输入要执行的ROOT命令:", "id");
			if(!shell || !shell.length) {
				return;
			}
			let jsonData = {
				type: 'runRootCmd',
				cmd: shell
			};
			sendJsonToServer(jsonData)
			.then(data => {
				appendConsole(data.content);
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}

        function runKernelCmdBtnClick() {
			var shell = prompt("请输入要执行的原生内核命令:", "id");
			if(!shell || !shell.length) {
				return;
			}
			let jsonData = {
				type: 'runKernelCmd',
				cmd: shell
			};
			sendJsonToServer(jsonData)
			.then(data => {
				appendConsole(data.content);
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}

        function installSuBtnClick() {
			let jsonData = {
				type: 'installSu',
			};
			sendJsonToServer(jsonData)
			.then(data => {
				appendConsole(data.content);
				if(data.err === '0') {
					g_lastSuFullPath = data.su_hide_full_path;
					const message = "安装部署su成功，su路径已复制到剪贴板。";
					alert(message);
				}
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}
		
		function injectSuInTempApp(appName) {
			let jsonData = {
				type: 'injectSuInTempApp',
				name: appName
			};
			sendJsonToServer(jsonData)
			.then(data => {
				appendConsole(data.content);
				if(data.errcode === '0') {
					showLoadingIndicator('请现在手动启动APP['+ appName +']');
					const timerid = setInterval(()=>{
						let jsonData = {
							type: 'getInjectSuInTempAppResult',
						};
						sendJsonToServer(jsonData)
						.then(data => {
							appendConsole(data.content);
							if(data.working !== '1') {
								clearInterval(timerid);
								hideLoadingIndicator();

								if(data.success === '1') {
									alert('已经授予ROOT权限到APP['+ appName +']');
								}
							}
						})
						.catch(error => {
							clearInterval(timerid);
							hideLoadingIndicator();
							alert('发送数据时发生错误');
							
						});
					}, 250);
				}
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}

		function showAppListModal() {
			var modal = document.getElementById("myAppListModal");
			modal.style.display = "block";
		}

		function hideAppListModal() {
			var modal = document.getElementById("myAppListModal");
			modal.style.display = "none";
		}

		function addAppListModalItem(txt, isSuForeverInject) {
			var listItems = document.getElementById('listAppItems');
			var div = document.createElement('div');
			div.className = 'list-item';
			div.innerHTML = txt;
			div.onclick = function(event) {
				const clickName = event.target.innerHTML;
				hideAppListModal();
				if(isSuForeverInject) {
					showFileListModal();
					getPrecheckAppFileList(clickName);
				} else {
					injectSuInTempApp(clickName);
				}
			}
			listItems.appendChild(div);
		}

		function cleanAppListModal() {
			var listItems = document.getElementById('listAppItems');
			while (listItems.firstChild) {
				listItems.removeChild(listItems.firstChild);
			}
		}
		
		function setAppListModalCheckbox(isSuForeverInject) {
			var showSystemAppsCheckbox = document.getElementById('showSystemApps');
			var showThirdPartyAppsCheckbox = document.getElementById('showThirdPartyApps');
			var showRunningAppsCheckbox = document.getElementById('showRunningApps');
			showSystemAppsCheckbox.disabled = !isSuForeverInject;
			showThirdPartyAppsCheckbox.disabled = !isSuForeverInject;
			showRunningAppsCheckbox.disabled = !isSuForeverInject;
		}

		function getAppList(isSuForeverInject) {
			cleanAppListModal();

			var showSystemAppsCheckbox = document.getElementById('showSystemApps');
			var showThirdPartyAppsCheckbox = document.getElementById('showThirdPartyApps');
			var showRunningAppsCheckbox = document.getElementById('showRunningApps');

			let jsonData = {
				type: 'getAppList',
				showSystemApp: showSystemAppsCheckbox.checked ? 1 : 0,
				showThirdApp: showThirdPartyAppsCheckbox.checked ? 1 : 0,
				showRunningApp: showRunningAppsCheckbox.checked ? 1 : 0,
			};
			sendJsonToServer(jsonData)
			.then(data => {
				for(let i = 0; i < data.content.length; i++) {
					addAppListModalItem(data.content[i], isSuForeverInject);
				}
				
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});

			
			showSystemAppsCheckbox.addEventListener('change', function() {
				getAppList(isSuForeverInject);
			});

			showThirdPartyAppsCheckbox.addEventListener('change', function() {
				getAppList(isSuForeverInject);
			});
			
			showRunningAppsCheckbox.addEventListener('change', function() {
				getAppList(isSuForeverInject);
			});
		}

		function showFileListModal() {
			var modal = document.getElementById("myFileListModal");
			modal.style.display = "block";
		}

		function hideFileListModal() {
			var modal = document.getElementById("myFileListModal");
			modal.style.display = "none";
		}

		function injectSuInForeverApp(appName, path) {
			let jsonData = {
				type: 'injectSuInForeverApp',
				name: appName,
				subname: path
			};
			sendJsonToServer(jsonData)
			.then(data => {
				if(data.errcode === '0') {
					alert('已永久寄生su环境至APP');
				}
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}

		function addFileListModalItem(appName, path, desc) {
			const filename = path.split('/').pop();
			var listItems = document.getElementById('listFileItems');
			var div = document.createElement('div');
			div.className = 'list-item';
			div.innerHTML = filename + desc;
			div.setAttribute('data-app', appName);
			div.setAttribute('data-path', path);
			div.onclick = function(event) {
				const appName = event.target.getAttribute('data-app');
				const path = event.target.getAttribute('data-path');
				hideFileListModal();
				injectSuInForeverApp(appName, path);
			}
			listItems.appendChild(div);
		}

		function cleanFileListModal() {
			var listItems = document.getElementById('listFileItems');
			while (listItems.firstChild) {
				listItems.removeChild(listItems.firstChild);
			}
		}

		function getPrecheckAppFileList(appName) {
			cleanFileListModal();
			let jsonData = {
				type: 'getPrecheckAppFileList',
				name: appName,
			};
			sendJsonToServer(jsonData)
			.then(data => {
				appendConsole(data.content);
				for(let i = 0; i < data.arr_map.length; i++) {
					const obj = data.arr_map[i];
					const keys = Object.keys(obj);
					const values = Object.values(obj);
					const firstKey = keys[0];
					const firstValue = values[0];
					addFileListModalItem(appName, firstKey, firstValue);
				}
				
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}


		function getInjectSuAppList(isSuForeverInject) {
			showAppListModal();
			setAppListModalCheckbox(isSuForeverInject);
			getAppList(isSuForeverInject);
		}

        function injectSuBtnClick() {
		    let isSuForeverInject = !confirm("请选择模式：\n\n点击确定选择：临时注入su\n点击取消选择：永久注入su");
			getInjectSuAppList(isSuForeverInject);
		}

        function uninstallSuBtnClick() {
			let jsonData = {
				type: 'uninstallSu',
			};
			sendJsonToServer(jsonData)
			.then(data => {
				appendConsole(data.content);
				if(data.err === '0') {
					g_lastSuFullPath = '';
				}
			})
			.catch(error => {
				alert('发送数据时发生错误');
			});
		}

        function copyConsoleBtnClick() {
			let consoleText = document.getElementById('console');
			copyToClipboard(consoleText.value);
			alert('已复制');
		}

        function clearConsoleBtnClick() {
			let consoleText = document.getElementById('console');
			consoleText.value = '';
		}

    </script>
	
</head>

<body>
	<div class="first-part">
	    <span class="head-tip">Super Kernel Root内核级完美隐藏ROOT演示</span>
		<span class="desc-tip">新一代SKRoot，挑战全网root检测手段，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，全程不需要暂停SELinux，实现真正的SELinux  0%触碰，通用性强，通杀所有内核，不需要内核源码，直接patch内核，兼容安卓APP直接JNI调用，稳定、流畅、不闪退。</span>
		<span class="warning-tip">当前是寄生模式，您可卸载原来的管理APP，避免管理APP被侦测</span>
		<div class="divider"></div>
	</div>

	<div class="second-part">
	   <div class="menu-list">
			<span class="menu-head-text">菜单功能列表：</span>
			<button class="btn" onclick="testRootBtnClick()">1.测试ROOT权限</button>
			<button class="btn" onclick="runRootCmdBtnClick()">2.执行ROOT命令</button>
			<button class="btn" onclick="runKernelCmdBtnClick()">3.执行原生内核命令</button>
			<button class="btn" onclick="installSuBtnClick()">4.安装部署su</button>
			<button class="btn" onclick="injectSuBtnClick()">5.注入su到指定进程</button>
			<button class="btn" onclick="uninstallSuBtnClick()">6.完全卸载清理su</button>
		</div>
		<div><div class="vertical"></div></div>
		<div class="output-list">
            <span class="menu-head-text">输出信息:</span>
			<div class="output-tool-list">
			    <button class="small-btn" onclick="copyConsoleBtnClick()">复制</button>
				<button class="small-btn" onclick="clearConsoleBtnClick()">清空</button>
			</div>
            <textarea id="console" class="console" placeholder=""></textarea>
            </div>
    </div>
	<div id="myAppListModal" class="modal">
		<div class="modal-content">
			<span id="myAppListClose" class="close">&times;</span>
			<h2>选择应用</h2>
			<div class="filter-input-container">
				<input type="text" id="filterAppInput" class="filter-input" placeholder="筛选...">
				<span id="myAppListClear" class="clear-input">&times;</span>
			</div>
			<div class="checkbox-container">
				<input type="checkbox" id="showSystemApps" name="showSystemApps">
				<label for="showSystemApps">系统应用</label>
				<input type="checkbox" id="showThirdPartyApps" name="showThirdPartyApps" checked>
				<label for="showThirdPartyApps">第三方应用</label>
				<input type="checkbox" id="showRunningApps" name="showRunningApps" checked>
				<label for="showRunningApps">正在运行</label>
			</div>
			<div class="list-items" id="listAppItems">
				<!-- 动态添加列表项 -->
			</div>
		</div>
	</div>
	<div id="myFileListModal" class="modal">
		<div class="modal-content">
			<span id="myFileListClose" class="close">&times;</span>
			<h2>选择文件</h2>
			<div class="filter-input-container">
				<input type="text" id="filterFileInput" class="filter-input" placeholder="筛选...">
				<span id="myFileListClear" class="clear-input">&times;</span>
			</div>
			<div class="list-items" id="listFileItems">
				<!-- 动态添加列表项 -->
			</div>
		</div>
	</div>
	<div id="loadingIndicator" class="loading-indicator">
		<div class="loading-box">
			<div class="loading-logo"></div>
			<div id="loadingText" class="loading-content"></div>
		</div>
	</div>
</body>

</html>


)***";

}

void writeToLog(const std::string & message, const char* logFile = "/data/local/tmp/root_server.log") {
    // FILE* file = fopen(logFile, "a");
    // if (file == nullptr) {
    //     perror("Error opening file");
    //     return;
    // }
    // fwrite(message.c_str(), sizeof(char), message.length(), file);
    // fwrite("\n", sizeof(char), 1, file);
    // fclose(file);
	//printf("%s\n", message.c_str());
}

std::string GetHttpHead_200(long lLen) {
    std::stringstream sstrHead;
    sstrHead << "HTTP/1.1 200 OK\r\n";
    sstrHead << "Access-Control-Allow-Origin: *\r\n";
    sstrHead << "Connection: keep-alive\r\n";
    sstrHead << "Content-Length: " << lLen << "\r\n";
    sstrHead << "Content-Type: text/html; charset=UTF-8\r\n";
    sstrHead << "\r\n";
    return sstrHead.str();
}


#endif /* _ROOT_SERVER_H_ */
