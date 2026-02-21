const RequestApi = (() => {
  function postText(path, bodyText = "") {
    const url = new URL(path, window.location.href);
    return fetch(url, { method: 'POST', body: bodyText });
  }

  async function sendCommand(cmd) {
    const resp = await postText('/sendCommand', cmd);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function getNewOutput() {
    const resp = await postText('/getNewOutput');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  return {
    sendCommand,
    getNewOutput
  };
})();
