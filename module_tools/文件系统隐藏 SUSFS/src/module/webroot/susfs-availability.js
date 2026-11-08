/* SUSFS is bundled in PLUS. Service availability changes status, never access. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  if (!root?.document) return;
  root.SKSusfsAvailability = factory({request:()=>RequestApi.filesManagerStatus()});
})(typeof window === 'undefined' ? null : window, function createAvailability(options) {
  const listeners = new Set();
  let current = Object.freeze({state:'available',managerState:'unknown',error:null});
  function publish(managerState,error=null) {
    current=Object.freeze({state:'available',managerState,error});
    for (const listener of listeners) listener(current);
    return current;
  }
  async function probe() {
    try { const value=await options.request(); return publish(value?.state || 'unknown'); }
    catch(error) { return publish('unavailable',error); }
  }
  return {get state(){return current.state;},get snapshot(){return current;},canAccess:()=>true,isAbsent:()=>false,
    ensure:()=>Promise.resolve(current),probe,start:probe,dispose(){listeners.clear();},
    subscribe(listener){listeners.add(listener);listener(current);return()=>listeners.delete(listener);}};
});
