const {JSDOM, VirtualConsole}=require('jsdom');
const {execFileSync}=require('child_process');
const {mkdtempSync,readFileSync,rmSync}=require('fs');
const {tmpdir}=require('os');const {join}=require('path');
const assert=require('assert');
const dir=mkdtempSync(join(tmpdir(),'nova-ui-'));
const wait=()=>new Promise(resolve=>setTimeout(resolve,30));
const role={id:3,role_key:'writer',display_name:'Yazar',active:1,system_role:0};
const group={id:2,group_key:'team',display_name:'Ekip',active:1};
const user={id:1,username:'admin',display_name:'Admin',role:'admin',active:true};
const settings={brand_text:'Test',surface_brightness:'18'};
const inventory={inventory:[{name:'mock:1',size:10}],configured:[],roles:[],groups:[]};
const responses={
 '/api/profile':{user,permissions:['agent.chat','agent.models.use','agent.history'],roles:[],groups:[]},
 '/api/admin/access/roles':{roles:[role],grants:[],permissions:['agent.chat','portal.view']},
 '/api/admin/access/groups':{groups:[group],members:[],roles:[]},
 '/api/admin/agent/models':inventory,'/api/agent/models':{models:[{tag:'mock:1',display_name:'Test model',default_model:1}]},
 '/api/agent/conversations':{conversations:[]},
 '/api/admin/state':{settings,users:[user]},
 '/api/admin/system/status':{services:{},disk:{},memory:{},models:[],issues:[]},
 '/api/admin/maviorkide/lab-status':{running:false,workspace_bytes:0,workspace_limit:1}
};
let calls=[];
function create(name){
 const errors=[], vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
 const dom=new JSDOM(readFileSync(join(dir,name),'utf8'),{runScripts:'dangerously',url:'https://test.example',virtualConsole:vc,beforeParse(w){
  w.fetch=async (url,opts={})=>{calls.push([url,opts.method||'GET']);return {ok:true,status:200,json:async()=>responses[url]||{ok:true}}};
  w.setInterval=()=>0;w.requestAnimationFrame=f=>f();w.confirm=()=>true;w.alert=()=>{};
 }});
 return {dom,errors};
}
(async()=>{try{
 execFileSync(process.env.PYTHON || 'python3',['tests/render_pages.py',dir]);
 let {dom,errors}=create('admin.html');await wait();
 assert.deepStrictEqual(errors,[],'admin page script errors');
 const d=dom.window.document;
 d.querySelector('[data-view="roles"]').click();await wait();
 assert(d.querySelector('#roleList').textContent.includes('Yazar'));
 assert(d.querySelector('#view-roles').classList.contains('active'));
 d.querySelector('[data-view="groups"]').click();await wait();assert(d.querySelector('#groupList').textContent.includes('Ekip'));
 d.querySelector('[data-view="agentmodels"]').click();await wait();assert(d.querySelector('#agentModelTag').textContent.includes('mock:1'));
 d.querySelector('[data-view="agentchat"]').click();await wait();assert(d.querySelector('#chatModel').textContent.includes('Test model'));
 d.querySelector('#profileToggle').click();await wait();assert.equal(d.querySelector('#profileOverlay').hidden,false);assert.equal(d.querySelector('#profileName').value,'Admin');
 assert.deepStrictEqual(errors,[],'admin interaction errors');dom.window.close();
 ({dom,errors}=create('private.html'));await wait();const priv=dom.window.document;
 assert(!priv.querySelector('#privateAgentOpen').classList.contains('hidden'));
 priv.querySelector('#privateAgentOpen').click();await wait();assert(priv.querySelector('#privateAgentModel').textContent.includes('Test model'));
 assert.deepStrictEqual(errors,[],'private page errors');dom.window.close();
 console.log('UI DOM smoke tests passed (simulated, not a real browser).');
 }catch(e){console.error(e);process.exitCode=1}finally{rmSync(dir,{recursive:true,force:true})}})();
