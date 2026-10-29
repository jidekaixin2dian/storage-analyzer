// Focused tests of the real report functions, with a minimal DOM adapter.
// These are simulated UI-state tests, not a browser rendering test.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const template = fs.readFileSync(process.argv[2], 'utf8');
const script = template.match(/<script>([\s\S]*?)<\/script>/)[1]
  .replace('__REPORT_DATA__', JSON.stringify({system:{}, coverage:{denied_count:1,
    denied:[{path:'中文 & <path>',reason:'disappeared',error:'gone'}]}}))
  .replace('__DELETE_CONFIG__', 'null');
const context = vm.createContext({
  document:{getElementById:()=>({}),addEventListener:()=>{}},
  btoa:s=>Buffer.from(s,'binary').toString('base64'),
  atob:s=>Buffer.from(s,'base64').toString('binary'),
  console, escape, unescape
});
vm.runInContext(script, context); // Also catches syntax and mount-time failures.
assert(context.renderCoverage().includes('扫描有遗漏'));
const capacityReport=context.renderSystem({disk_total:'100 GB',disk_used:'70 GB',disk_free:'30 GB',os:'Windows synthetic'},{});
assert(capacityReport.includes('100 GB') && capacityReport.includes('30 GB'));
assert(capacityReport.includes('class="stats"'));
assert(!capacityReport.includes('capacity-unknown'));

assert(context.renderCoverage().includes('中文 &amp; &lt;path&gt;'));
const rank=context.renderTop5([{rank:1,name:'合成资料',size:'2 MB',tier:'yellow',type:'个人资料',path:'C:/case/<keep> & review',note:'先人工核对用途'}]);
for(const fact of ['合成资料','2 MB','个人资料','C:/case/&lt;keep&gt; &amp; review','先人工核对用途','路径与依据']) assert(rank.includes(fact));
assert(context.renderTop5([]).includes('本次分析未提供占用排行'));

assert(context.renderGreen([{name:'cache',path:'fixture',trash_paths:['fixture'],
  evidence:'<verified>',commands:[{label:'manual',cmd:'review & keep'}]}]).includes('&lt;verified&gt;'));
assert(!context.renderGreen([{name:'cache',path:'fixture',trash_paths:['fixture']}]).includes('del-btn'));
assert(context.renderGreen([{name:'cache'}]).includes('未提供核实依据'));
assert.deepEqual(Array.from(context.actionConfirmation(['one','two'],'trash').paths), ['one','two']);
assert(context.actionConfirmation(['folder'],'rm').impact.includes('全部子目录和文件'));
assert(context.actionConfirmation(['folder'],'rm').impact.includes('不可恢复'));

function card(paths){
  const status={};
  const state={cleaned:false,removed:false};
  return {state,status,dataset:{paths:Buffer.from(JSON.stringify(paths)).toString('base64')},
    querySelector:()=>status,
    querySelectorAll:()=>[{remove:()=>state.removed=true}],
    closest:()=>({classList:{add:()=>state.cleaned=true}})};
}
const partial=card(['first','second','third']);
context.actionResult(partial,{ok:false,status:'partial',error:'cancelled',results:[
  {path:'first',status:'completed'},{path:'second',status:'cancelled'},
  {path:'third',status:'not_attempted'}]},'trash');
assert.equal(Buffer.from(partial.dataset.paths,'base64').toString(),'["second","third"]');
assert(partial.status.textContent.includes('部分完成：1/3'));
assert(!partial.state.cleaned);
assert(!partial.state.removed);
const pending=card(['third']);
context.actionResult(pending,{results:[{path:'third',status:'not_attempted'}]},'trash');
assert(pending.status.textContent.includes('尚未执行'));
const done=card(['first']);
context.actionResult(done,{ok:true,results:[{path:'first',status:'completed'}]},'rm');
assert(done.state.cleaned && done.state.removed);
assert(done.status.textContent.includes('未测量磁盘净释放量'));
const missing=card(['gone']);
context.actionResult(missing,{ok:true,results:[{path:'gone',status:'already_missing'}]},'rm');
assert(missing.status.textContent.includes('本次未删除文件'));
const unknown=card(['one']);
context.actionResult(unknown,{ok:false,error:'连接失败，操作结果未知'},'rm');
assert(!unknown.state.cleaned && !unknown.state.removed);
assert(unknown.status.textContent.includes('结果未知'));
console.log('Report runtime: rendering and per-path state checks passed (simulated DOM).');

// A cancelled or unsupported dialog must never resolve to approval.
(async()=>{
  assert.equal(await context.requestConfirmation(['one'],'trash'),false);
  const elements={};
  const listeners={};
  elements['action-confirm']={open:false,returnValue:'',
    addEventListener:(name,callback)=>listeners[name]=callback,
    showModal(){this.open=true;}};
  for(const id of ['confirm-title','confirm-impact','confirm-count','confirm-paths','confirm-submit']) elements[id]={};
  context.document.getElementById=id=>elements[id];
  let request=context.requestConfirmation(['中文 <unsafe> & path'],'trash');
  assert(elements['confirm-paths'].innerHTML.includes('&lt;unsafe&gt; &amp;'));
  assert.equal(elements['action-confirm'].returnValue,'cancel');
  elements['action-confirm'].open=false;
  listeners.close();
  assert.equal(await request,false);
  request=context.requestConfirmation(['only-fixture'],'trash');
  elements['action-confirm'].returnValue='confirm';
  elements['action-confirm'].open=false;
  listeners.close();
  assert.equal(await request,true);
  console.log('Confirmation dialog: explicit approval, cancel, unsupported browser and path escaping passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
