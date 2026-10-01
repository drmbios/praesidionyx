import {PolicyDemo} from './policy.mjs';
const $ = id => document.getElementById(id);
const demo = new PolicyDemo();
const scenarios = {
  injection: {name:'page-reader',task:'Read a page and inspect an unexpected instruction.',path:'notes.txt',content:'Agent owned.',title:'A harmless-looking article',body:'Useful information from an external source.',fixture:'injection'},
  research: {name:'research-assistant',task:'Read external research, then request a summary write.',path:'reports/summary.txt',content:'A summary derived from untrusted research.',title:'Notes on supervised agents',body:'Exact capabilities bound what tools may do. Provenance follows data as it is summarized.',fixture:'research'},
  delegation: {name:'child-researcher',task:'A child inherits a narrower path than its parent.',path:'notes.txt',content:'A write outside the inherited scope.',title:'A delegated research task',body:'The parent may write notes.txt. The child is restricted to reports/summary.txt. Try both paths.',fixture:'research'}
};
function element(tag,text,className) { const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(className)e.className=className; return e; }
function render() {
  $('taint').textContent=demo.taint.toUpperCase(); $('taint').style.color=demo.taint==='untrusted'?'#a47425':'#6947d5';
  $('budget').textContent=demo.budget;
  $('agent-state').textContent=demo.state.toUpperCase(); $('agent-state').className='badge '+(demo.state==='running'?'green':'red');
  $('scope').textContent=demo.scope||'No write authority'; $('delegation').textContent=demo.scenario==='delegation'?'Floor: reports/summary.txt':'Root grant';
  const p=demo.pending; $('approval-status').textContent=p?p.status.toUpperCase():'NO REQUEST';
  $('approval-status').className='badge '+(p?(p.status==='approved'?'green':p.status==='denied'?'red':'amber'):'neutral');
  $('approve').disabled=$('deny').disabled=!p||p.status!=='pending'||demo.state!=='running';
  $('retry').disabled=!p||p.status==='pending'||demo.state!=='running';
  $('approval-detail').textContent=p?`Exact path: ${p.path}. Content and context revision ${demo.revision} are bound to this decision. The write has not executed.`:'An untrusted write is held here until you decide. Approval authorizes one exact retry.';
  $('files').replaceChildren();
  for(const [path,content] of Object.entries(demo.files)) {
    const file=element('div',undefined,'file'); file.append(element('strong','▤ '+path),element('p',content)); $('files').append(file);
  }
  if(!Object.keys(demo.files).length)$('files').append(element('p','No files written yet.','empty'));
  $('event-list').replaceChildren();
  for(const event of demo.events) {
    const li=element('li'); li.append(element('span',String(event.sequence).padStart(2,'0'),'subtle'),element('span',event.operation,'op'),element('span',event.outcome.replaceAll('_',' '),'outcome '+event.outcome),element('span',event.detail,'event-detail')); $('event-list').append(li);
  }
  if(!demo.events.length)$('event-list').append(element('li','Actions and decisions will appear here.','empty'));
  const last=demo.events.at(-1); if(last){$('result').textContent=last.detail; $('result').dataset.outcome=last.outcome;}
}
function run(fn) {fn();render();}
function reset(scenario=demo.scenario) {
  demo.reset(scenario); if(scenario==='research')demo.changeScope('reports/summary.txt');
  const s=scenarios[scenario]; $('agent-name').textContent=s.name; $('agent-task').textContent=s.task;
  $('target-path').value=s.path; $('write-content').value=s.content; $('doc-title').textContent=s.title; $('doc-body').textContent=s.body; $('fixture').textContent=s.fixture;
  $('hidden-instruction').hidden=scenario!=='injection';
  $('read-page').textContent=scenario==='delegation'?'Receive forwarded page →':'Read external page →'; $('scope-select').value=demo.scope;
  $('result').textContent=scenario==='delegation'?'Attempt notes.txt to test the inherited scope, then try reports/summary.txt.':'Start by reading the external page, then attempt the requested write.';
  delete $('result').dataset.outcome;
  document.querySelectorAll('[data-scenario]').forEach(b=>b.classList.toggle('active',b.dataset.scenario===scenario)); render();
}
$('read-page').addEventListener('click',()=>run(()=>demo.observe()));
$('attempt-write').addEventListener('click',()=>run(()=>demo.write($('target-path').value,$('write-content').value)));
$('change-context').addEventListener('click',()=>run(()=>demo.changeContext()));
$('approve').addEventListener('click',()=>run(()=>demo.decide(true)));
$('deny').addEventListener('click',()=>run(()=>demo.decide(false)));
$('retry').addEventListener('click',()=>run(()=>demo.retry()));
$('reset').addEventListener('click',()=>reset());
$('scope-select').addEventListener('change',e=>run(()=>{demo.changeScope(e.target.value==='none'?'':e.target.value);demo.record('capability.select','changed','A different simulated grant selected. Pending approvals cleared.');}));
document.querySelectorAll('[data-scenario]').forEach(b=>b.addEventListener('click',()=>reset(b.dataset.scenario)));
function route() {
  let view=location.hash.slice(1); if(!['playground','memory','evidence','architecture'].includes(view))view='playground';
  document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!=='view-'+view);
  document.querySelectorAll('[data-view]').forEach(a=>{const active=a.dataset.view===view;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
}
window.addEventListener('hashchange',route);route();reset();
// Fixed slot visualization. Real runtime pages use byte-based context estimates.
const memory={history:[{id:1,label:'user',content:'Initial user task: collect research with human supervision.'}],resident:[1],snapshot:null,taint:'user'};
function renderMemory() {
  $('memory-pages').replaceChildren();
  for(const id of memory.resident) {
    const page=memory.history.find(p=>p.id===id); const block=element('div',undefined,'memory-page');
    block.append(element('div',`PAGE ${page.id} · ${page.label.toUpperCase()}`,'label'),element('p',page.content)); $('memory-pages').append(block);
  }
  $('memory-capacity').textContent=memory.resident.length+' / 3 PAGES'; $('resident-count').textContent=memory.resident.length;
  $('history-count').textContent=memory.history.length; $('snapshot-count').textContent=memory.snapshot?1:0;
  $('memory-taint').textContent=memory.taint==='untrusted'?'Untrusted, even after rollback.':'User context'; $('memory-rollback').disabled=!memory.snapshot;
}
$('memory-add').addEventListener('click',()=>{
  const id=memory.history.length+1; memory.history.push({id,label:'untrusted',content:`External research page ${id}: derived data retains the source provenance.`});
  memory.resident.push(id);if(memory.resident.length>3)memory.resident.shift();memory.taint='untrusted';
  $('memory-result').textContent='External page added. Oldest whole page evicted if needed. Provenance is now untrusted.';renderMemory();
});
$('memory-checkpoint').addEventListener('click',()=>{memory.snapshot=[...memory.resident];$('memory-result').textContent='Resident page IDs saved. Trust labels, history and budgets are not reset.';renderMemory();});
$('memory-rollback').addEventListener('click',()=>{if(!memory.snapshot)return;memory.resident=[...memory.snapshot];$('memory-result').textContent='Resident pages restored. Agent provenance remains '+memory.taint+'; stored history remains intact.';renderMemory();});renderMemory();
let recording=null, playTimer=null;
function stopReplay(){if(playTimer!==null)clearTimeout(playTimer);playTimer=null;$('replay').textContent='Replay at 4× ▷';}
async function loadEvidence() {
  try {
    const response=await fetch('demo.cast');if(!response.ok)throw new Error('Recording unavailable');
    const lines=(await response.text()).trim().split('\n').map(line=>JSON.parse(line));
    recording=lines.slice(1).filter(e=>e[1]==='o');
    $('terminal-output').textContent=recording.map(e=>e[2]).join('').replaceAll('\r','');
  } catch { $('terminal-output').textContent='The recording could not be loaded. Use the transcript link or the full repository verification report.';$('replay').disabled=true; }
  try {const response=await fetch('verification.json');if(!response.ok)throw new Error();const v=await response.json();$('test-count').textContent=v.rust_tests;$('verification-date').textContent=`Local verification: ${v.date} · ${v.platform}. ${v.note}`;} catch {$('test-count').textContent='See report';}
}
$('replay').addEventListener('click',()=>{
  if(playTimer!==null){stopReplay();return;}if(!recording?.length)return;
  $('terminal-output').textContent='';$('replay').textContent='Stop replay ■';let index=0;
  function next(){const event=recording[index];$('terminal-output').textContent+=event[2].replaceAll('\r','');$('terminal-output').scrollTop=$('terminal-output').scrollHeight;index++;if(index>=recording.length){stopReplay();return;}playTimer=setTimeout(next,Math.max(0,(recording[index][0]-event[0])*250));}
  next();
});
$('copy-command').addEventListener('click',async()=>{
  try{await navigator.clipboard.writeText('python3 scripts/quickstart.py');$('copy-command').textContent='Copied ✓';}catch{$('copy-command').textContent='Select the command to copy';}
});loadEvidence();
