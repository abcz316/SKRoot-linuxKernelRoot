const RequestApi = (() => {
  function postText(path, bodyText = "") {
    const url = new URL(path, window.location.href);
    return fetch(url, { method: 'POST', body: bodyText });
  }

  async function getCandidatesPkgJson() {
    const resp = await postText('/getCandidatesPkgJson');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function getTargetPkgJson() {
    const resp = await postText('/getTargetPkgJson');
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  async function setTargetPkgJson(json) {
    const resp = await postText('/setTargetPkgJson', json);
    return resp.ok ? await resp.text() : ('HTTP ' + resp.status);
  }

  return {
    getCandidatesPkgJson,
    getTargetPkgJson,
    setTargetPkgJson
  };
})();
