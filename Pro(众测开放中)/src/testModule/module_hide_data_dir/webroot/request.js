const RequestApi = (() => {
  function postText(path, bodyText = "") {
    const url = new URL(path, window.location.href);
    return fetch(url, { method: 'POST', body: bodyText });
  }

  async function getHiddenDirsJson() {
    const resp = await postText('/getHiddenDirsJson');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function setHiddenDirsJson(json) {
    const resp = await postText('/setHiddenDirsJson', json);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function checkFileExist(filePath) {
    const resp = await postText('/checkFileExist', filePath);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  return {
    getHiddenDirsJson,
    setHiddenDirsJson,
    checkFileExist
  };
})();
