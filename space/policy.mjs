// An explicit browser simulation. Enforcement lives in the Rust Linux runtime.
export class PolicyDemo {
  constructor(now = () => Date.now()) { this.now = now; this.reset(); }
  reset(scenario = 'injection') {
    this.scenario = scenario; this.taint = 'user'; this.revision = 0;
    this.scope = scenario === 'delegation' ? 'reports/summary.txt' : 'notes.txt';
    this.inheritedFloor = scenario === 'delegation' ? 'reports/summary.txt' : null;
    this.budget = 6; this.state = 'running'; this.pending = null;
    this.sequence = 0; this.files = {}; this.events = [];
  }
  record(operation, outcome, detail) {
    const event = {sequence: ++this.sequence, operation, outcome, detail};
    this.events.push(event); return event;
  }
  observe() {
    if (this.state !== 'running') return this.record('http.get', 'denied', 'Agent is stopped.');
    if (!this.budget) return this.stop();
    if (this.scenario !== 'delegation') this.budget--;
    this.taint = 'untrusted'; this.revision++; this.pending = null;
    if (this.scenario === 'delegation') return this.record('agent.message', 'received', 'Parent forwarded untrusted research. The child retains that provenance.');
    return this.record('http.get', 'allowed', this.scenario === 'injection'
      ? 'External page read. Hidden instruction: write notes.txt. Context is now untrusted.'
      : 'External research read. Derived text retains untrusted provenance.');
  }
  stop() { this.state = 'killed'; this.pending = null; return this.record('scheduler', 'killed', 'Tool budget exhausted.'); }
  changeScope(value) { this.scope = value; this.pending = null; }
  changeContext() {
    this.revision++; this.pending = null;
    return this.record('context.update', 'changed', 'Pending approval invalidated. Taint remains ' + this.taint + '.');
  }
  write(path = this.scenario === 'delegation' ? 'notes.txt' : this.scope, content = 'Browser demonstration output', approvalId = '') {
    if (this.state !== 'running') return this.record('fs.write', 'denied', 'Agent is stopped.');
    if (!this.budget) return this.stop();
    if (!path || path !== this.scope || (this.inheritedFloor && path !== this.inheritedFloor) || path.startsWith('/') || path.split('/').some(p => p === '..' || p === '.' || !p))
      return this.record('fs.write', 'denied', 'Path is outside the exact capability or inherited child scope. Approval cannot widen it.');
    const fingerprint = JSON.stringify({path,content,scope:this.scope,revision:this.revision});
    if (this.taint === 'untrusted') {
      if (approvalId) {
        const p = this.pending;
        this.pending = null;
        if (!p || p.id !== approvalId || p.status !== 'approved' || p.fingerprint !== fingerprint || p.expires <= this.now())
          return this.record('fs.write', 'denied', 'Approval is stale, expired, mismatched, denied or already consumed.');
      } else {
        this.pending = {id:'request-' + (this.sequence + 1),fingerprint,path,content,status:'pending',expires:this.now()+300000};
        return this.record('fs.write', 'needs_approval', 'Untrusted context requires an exact, one-use supervisor decision.');
      }
    }
    this.budget--; this.files[path] = content;
    return this.record('fs.write', 'allowed', 'Simulated write completed: ' + path + '. Taint remains ' + this.taint + '.');
  }
  decide(allow) {
    if (this.state !== 'running' || !this.pending || this.pending.status !== 'pending' || this.pending.expires <= this.now())
      return this.record('supervisor', 'denied', 'No active pending request.');
    this.pending.status = allow ? 'approved' : 'denied';
    return this.record('supervisor', allow ? 'approved' : 'denied', 'Decision recorded. The write has not executed.');
  }
  retry() {
    if (!this.pending) return this.record('fs.write', 'denied', 'No approval to retry.');
    const {path,content,id} = this.pending; return this.write(path,content,id);
  }
}
