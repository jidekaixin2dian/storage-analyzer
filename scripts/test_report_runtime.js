// Focused tests of the real report functions, with a minimal DOM adapter.
// These are simulated UI-state tests, not a browser rendering test.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const template = fs.readFileSync(process.argv[2], 'utf8');
const script = template.match(/<script>([\s\S]*?)<\/script>/)[1]
  .replace('__REPORT_DATA__', JSON.stringify({system:{}, coverage:{denied_count:1,
    denied:[{path:'中文 & <path>',reason:'disappeared',error:'gone'}]}}))
  .replace('__DELETE_CONFIG__', '{"endpoint":"/action","token":"synthetic"}');
const clipboard = [];
let copyClick;
const context = vm.createContext({
  document:{getElementById:()=>({appendChild:()=>{},style:{}}),
    addEventListener:(type,handler)=>{if(type==='click') copyClick=handler;},
    createElement:()=>({style:{}})},
  navigator:{clipboard:{writeText:async text=>clipboard.push(text)}},
  btoa, atob, TextDecoder, Uint8Array, setInterval:()=>0, setTimeout:()=>0,
  fetch:async()=>({ok:true}),
  console, escape, unescape
});
vm.runInContext(script, context); // Also catches syntax and mount-time failures.
const run = source => vm.runInContext(source, context);

assert(context.renderCoverage().includes('扫描有遗漏'));
const capacityReport=context.renderSystem({disk_total:'100 GB',disk_used:'70 GB',disk_free:'30 GB',os:'Windows synthetic'},{});
assert(capacityReport.includes('100 GB') && capacityReport.includes('30 GB'));
assert(capacityReport.includes('class="stats"'));
assert(!capacityReport.includes('capacity-unknown'));
const unknownCapacity=context.renderSystem({disk_total:'?',disk_used:'?',disk_free:'?',disk_name:'X:\\',
  disks:[{name:'X:',total:'?',used:'?',free:'?',capacity_error:'PermissionError: denied'},
    {name:'Y:\\',total:'?',used:'?',free:'?',capacity_error:'PermissionError: second denial'}]},{});
assert(unknownCapacity.includes('容量未知') && unknownCapacity.includes('PermissionError: denied'));
assert(unknownCapacity.includes('second denial'));
assert(!unknownCapacity.includes('NaN%') && !unknownCapacity.includes('width:0%'));
const volumeCoverage=context.renderCoverage({denied_count:1,denied:[],volumes:[
  {root:'C:\\',files:1,directories:1,bytes:2048},
  {root:'D:\\',files:0,directories:0,bytes:null}]},
  {disks:[{name:'C:',total:'1 KB'}]});
assert(volumeCoverage.includes('已读 2.00 KB 逻辑字节 · 容量快照 1 KB'));
assert(volumeCoverage.includes('已读逻辑字节超过容量快照'));
assert(volumeCoverage.includes('容量快照 未知') && volumeCoverage.includes('未知 逻辑字节'));
const smallVolume = {volumes:[{root:'C:\\',files:1,directories:1,bytes:512*1024}]};
assert(!context.renderCoverage(smallVolume,{disks:[{name:'C:',total:'1 MB'}]})
  .includes('超过容量快照'));
assert(context.renderCoverage(smallVolume,{disks:[{name:'C:',total:'0.5 MB',total_bytes:524287}]})
  .includes('超过容量快照'));
const systemPartial = context.renderSystemSpace({items:[{name:'WSL',partial:true,present:false}]});
assert(systemPartial.includes('探测不完整') && !systemPartial.includes('未检测到'));

assert(context.renderCoverage().includes('中文 &amp; &lt;path&gt;'));
const rank=context.renderTop5([{rank:1,name:'合成资料',size:'2 MB',tier:'yellow',type:'个人资料',path:'C:/case/<keep> & review',note:'先人工核对用途'}]);
for(const fact of ['合成资料','2 MB','个人资料','C:/case/&lt;keep&gt; &amp; review','先人工核对用途','路径与依据']) assert(rank.includes(fact));
assert(context.renderTop5([]).includes('本次分析未提供占用排行'));

assert(context.renderGreen([{name:'cache',path:'fixture',trash_paths:['fixture'],
  evidence:'<verified>',commands:[{label:'manual',cmd:'review & keep'}]}]).includes('&lt;verified&gt;'));
assert(context.renderGreen([{name:'cache',path:'fixture',trash_paths:['fixture']}]).includes('del-btn'));
assert(context.renderGreen([{name:'cache'}]).includes('未提供核实依据'));
assert.deepEqual(Array.from(context.actionConfirmation(['one','two'],'trash').paths), ['one','two']);
assert(context.actionConfirmation(['folder'],'rm').impact.includes('全部子目录和文件'));
assert(context.actionConfirmation(['folder'],'rm').impact.includes('不可恢复'));

// Exercise the real codec and per-path result state inside its lexical scope.
run(`
  const unicodePaths=['C:\\\\Users\\\\张三\\\\缓存','/tmp/缓存 😀','\\\\\\\\server\\\\共享\\\\资料'];
  globalThis.unicodeRoundTrip=decodeB64(b64(unicodePaths));
  for(const value of ['not base64!',b64(['one'])+' ',btoa('not JSON'),btoa('"'+String.fromCharCode(255)+'"')]){
    let rejected=false; try{decodeB64(value);}catch(e){rejected=true;}
    if(!rejected) throw new Error('invalid base64/JSON was accepted');
  }
  function card(paths){
    const status={}; const state={cleaned:false,removed:false};
    return {state,status,dataset:{paths:b64(paths)},querySelector:()=>status,
      querySelectorAll:()=>[{remove:()=>state.removed=true}],
      closest:selector=>selector==='.item'
        ? {classList:{add:()=>state.cleaned=true,contains:()=>state.cleaned}}
        : {classList:{add:()=>state.cleaned=true}}};
  }
  globalThis.partial=card(['first','second','third']);
  actionResult(partial,{ok:false,status:'partial',error:'cancelled',results:[
    {path:'first',status:'completed'},{path:'second',status:'cancelled'},
    {path:'third',status:'not_attempted'}]},'trash');
  globalThis.pending=card(['third']);
  actionResult(pending,{results:[{path:'third',status:'not_attempted'}]},'trash');
  globalThis.done=card(['first']);
  actionResult(done,{ok:true,results:[{path:'first',status:'completed'}]},'rm');
  globalThis.missing=card(['gone']);
  actionResult(missing,{ok:true,results:[{path:'gone',status:'already_missing'}]},'rm');
  globalThis.unknown=card(['one']);
  actionResult(unknown,{ok:false,error:'连接失败，操作结果未知'},'rm');
`);
assert.deepEqual(Array.from(run('unicodeRoundTrip')), ['C:\\Users\\张三\\缓存','/tmp/缓存 😀','\\\\server\\共享\\资料']);
const partial=run('partial');
assert.equal(Buffer.from(partial.dataset.paths,'base64').toString(),'["second","third"]');
assert(partial.status.textContent.includes('部分完成：1/3'));
assert(!partial.state.cleaned && !partial.state.removed);
assert(run('pending').status.textContent.includes('尚未执行'));
assert(run('done').state.cleaned && run('done').state.removed);
assert(run('done').status.textContent.includes('未测量磁盘净释放量'));
assert(run('missing').status.textContent.includes('本次未删除文件'));
assert(!run('unknown').state.cleaned && !run('unknown').state.removed);
assert(run('unknown').status.textContent.includes('结果未知'));

// Batch collection must preserve Unicode/backslashes and only disable local controls.
const actionChecks=run(`(async()=>{
  const paths=['C:\\\\Users\\\\张三\\\\缓存','/tmp/缓存 😀','\\\\\\\\server\\\\共享\\\\资料'];
  const status={}; const sectionStatus={};
  const wrap={dataset:{paths:b64(paths),open:b64(paths)},querySelector:()=>status,
    querySelectorAll:()=>[],closest:()=>({classList:{contains:()=>false,add:()=>{}}})};
  const secActions={querySelector:()=>sectionStatus,querySelectorAll:()=>[]};
  const sec={querySelectorAll:()=>[wrap]};
  const batchButton={closest:selector=>selector==='.sec-actions'?secActions:sec};
  const cardButton={closest:()=>wrap};
  globalThis.requests=[];
  globalThis.fetch=async(endpoint,options)=>{
    const req=JSON.parse(options.body);
    requests.push(req);
    // Keep the synthetic card's targets available for the next entry point.
    return {json:async()=>({ok:false,error:'synthetic failure',results:[]})};
  };
  globalThis.confirmedPaths=[];
  requestConfirmation=async target=>{confirmedPaths.push(target);return true;};
  await doBatch(batchButton,'trash');
  await doDelete(cardButton,'rm');
  await doOpen(cardButton);
  for(const value of ['not base64!',btoa('not JSON'),btoa('"'+String.fromCharCode(255)+'"'),b64('one'),b64(['one',null])]){
    wrap.dataset.paths=value;
    wrap.dataset.open=value;
    await doBatch(batchButton,'trash');
    await doDelete(cardButton,'rm');
    await doOpen(cardButton);
    if(!sectionStatus.textContent.includes('操作未发送') || !status.textContent.includes('操作未发送')){
      throw new Error('invalid report data did not show a local error');
    }
  }

  const own={disabled:false}, unrelated={disabled:false}, previouslyDisabled={disabled:true};
  document.querySelectorAll=()=>[own,unrelated,previouslyDisabled];
  let release;
  fetch=(endpoint,options)=>new Promise(resolve=>{release=()=>resolve({json:async()=>({ok:true})});});
  const actionWrap={querySelector:()=>status,querySelectorAll:()=>[own,previouslyDisabled]};
  const pending=postAction(actionWrap,['one'],'rm');
  if(!own.disabled || unrelated.disabled) throw new Error('controls disabled outside action container');
  release(); await pending;
  if(own.disabled || unrelated.disabled || !previouslyDisabled.disabled) throw new Error('button states not restored');
  markServerDown=()=>{};
  const failedResponses=[
    async()=>({json:async()=>({ok:false,error:'request rejected'})}),
    async()=>({json:async()=>{throw new SyntaxError('synthetic JSON error');}}),
    async()=>{throw new Error('synthetic network failure');},
    ()=>{throw new Error('synthetic synchronous failure');}
  ];
  for(const failed of failedResponses){
    fetch=failed;
    const res=await postAction(actionWrap,['one'],'rm');
    if(res.ok || own.disabled || unrelated.disabled || !previouslyDisabled.disabled){
      throw new Error('controls not restored after request failure');
    }
  }
})()`);
actionChecks.then(async()=>{
  const paths = ['C:\\Users\\张三\\缓存','/tmp/缓存 😀','\\\\server\\共享\\资料'];
  assert.deepEqual(Array.from(run('requests'), req=>req.mode), ['trash','rm','open']);
  for(const req of run('requests')) assert.deepEqual(req.paths, paths);
  assert.deepEqual(Array.from(run('confirmedPaths'), values=>Array.from(values)), [paths,paths]);
  const commands = ['pnpm store prune', 'Write-Output "\\\\server\\共享\\缓存 😀 & 资料"', '123'];
  const button = {dataset:{},classList:{add:()=>{},remove:()=>{}}};
  const event = {target:{closest:()=>button},stopPropagation:()=>{}};
  for(const command of commands){
    button.dataset.cmd=context.copyBtn(command).match(/data-cmd="([^"]+)"/)[1];
    await copyClick(event);
  }
  button.dataset.cmd=btoa('not a JSON command');
  await copyClick(event);
  assert.equal(button.textContent,'复制失败');
  assert.deepEqual(clipboard, commands);
  console.log('Report runtime: rendering, Unicode paths and per-path state checks passed (simulated DOM).');
  console.log('Single-card, batch, open and copy: exact input, invalid-data rejection and scoped recovery passed.');
}).catch(error=>{console.error(error);process.exitCode=1;});

// A cancelled or unsupported dialog must never resolve to approval.
(async()=>{
  const confirmContext=vm.createContext({
    document:{getElementById:()=>({appendChild:()=>{},style:{}}),addEventListener:()=>{},createElement:()=>({style:{}})},
    btoa, atob, TextDecoder, Uint8Array, setInterval:()=>0,
    fetch:async()=>({ok:true}), console
  });
  vm.runInContext(script.replace('const DELETE = {"endpoint":"/action","token":"synthetic"};',
    'const DELETE = null;'),confirmContext);
  assert(!confirmContext.renderGreen([{name:'cache',path:'fixture',trash_paths:['fixture']}]).includes('del-btn'));
  confirmContext.document.getElementById=()=>({});
  assert.equal(await confirmContext.requestConfirmation(['one'],'trash'),false);
  const elements={};
  const listeners={};
  elements['action-confirm']={open:false,returnValue:'',
    addEventListener:(name,callback)=>listeners[name]=callback,
    showModal(){this.open=true;}};
  for(const id of ['confirm-title','confirm-impact','confirm-count','confirm-paths','confirm-submit']) elements[id]={};
  confirmContext.document.getElementById=id=>elements[id];
  let request=confirmContext.requestConfirmation(['中文 <unsafe> & path'],'trash');
  assert(elements['confirm-paths'].innerHTML.includes('&lt;unsafe&gt; &amp;'));
  assert.equal(elements['action-confirm'].returnValue,'cancel');
  elements['action-confirm'].open=false;
  listeners.close();
  assert.equal(await request,false);
  request=confirmContext.requestConfirmation(['only-fixture'],'trash');
  elements['action-confirm'].returnValue='confirm';
  elements['action-confirm'].open=false;
  listeners.close();
  assert.equal(await request,true);
  console.log('Confirmation dialog: explicit approval, cancel, unsupported browser and path escaping passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
