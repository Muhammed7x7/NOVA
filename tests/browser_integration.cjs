const {chromium:playwright}=require('playwright-core');
const chromium=require('@sparticuz/chromium');
const assert=require('assert');
const base=process.env.NOVA_TEST_URL;
if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(base||'')) throw Error('Only a temporary loopback server is allowed');
(async()=>{
 const args=chromium.args.filter(a=>!['--disable-web-security','--allow-running-insecure-content'].includes(a));
 let browser=await playwright.launch({executablePath:await chromium.executablePath(),args,headless:true});
 const errors=[];
 try{
  const desktop=await browser.newContext({viewport:{width:1280,height:900}}),page=await desktop.newPage();
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base);await page.locator('#specialOpen').click();await page.locator('#specialChoices [data-id="admin"]').click();
  await page.locator('#specialPassword').fill('temporary-password-123');await page.locator('#specialPasswordForm button[type="submit"],#specialPasswordForm button:not([type])').first().click();
  await page.waitForURL('**/admin');assert(await page.locator('#menuToggle').isVisible());
  async function navigate(view){await page.locator('#menuToggle').click();await page.locator(`[data-view="${view}"]`).click();await page.locator('#menuClose').click();}
  await navigate('roles');await page.locator('#roleCreate [name=key]').fill('test-role');await page.locator('#roleCreate [name=display_name]').fill('Test Role');await page.locator('#roleCreate button').click();await page.locator('#roleNotice').getByText('Rol oluşturuldu.').waitFor();
  await navigate('groups');await page.locator('#groupCreate [name=key]').fill('test-group');await page.locator('#groupCreate [name=display_name]').fill('Test Group');await page.locator('#groupCreate button').click();await page.locator('#groupNotice').getByText('Grup oluşturuldu.').waitFor();
  await page.locator('#profileToggle').click();await page.locator('#profileName').fill('Yeni İsim');await page.locator('#profileNameForm button').click();await page.getByText('Görünen ad kaydedildi.').waitFor();await page.locator('#profileClose').click();
  await navigate('agentmodels');await page.locator('#agentModelTag option[value="test:model"]').waitFor({state:"attached"});await page.locator('#agentModelTag').selectOption('test:model');assert.equal(await page.locator('#agentModelName').inputValue(),'Test model');
  await navigate('agentchat');await page.locator('#chatModel option[value="test:model"]').waitFor({state:"attached"});await page.locator('#chatModel').selectOption('test:model');await page.locator('#chatInput').fill('merhaba');await page.locator('#chatForm button').click();await page.locator('#chatMessages').getByText('Yanıt: merhaba').waitFor();
  await desktop.close();await browser.close();
  browser=await playwright.launch({executablePath:await chromium.executablePath(),args,headless:true});
  const mobile=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true}),mp=await mobile.newPage();mp.on('pageerror',e=>errors.push(e.message));
  await mp.goto(base);await mp.locator('#standardForm [name=username]').fill('tester');await mp.locator('#standardForm [name=key]').fill('tester-password');await mp.locator('#standardForm button').click();await mp.waitForURL('**/private');
  await mp.locator('#normalMenuToggle').click();await mp.locator('#privateRepoOpen').click();
  await mp.locator('#privateRepoInput').fill('echo hello');await mp.locator('#privateRepoForm button').click();await mp.locator('#privateRepoNotice').getByText('Maviorkide Repo Laboratuvarı çalışmıyor').waitFor();
  await mp.locator('#privateRepoClose').click();await mp.locator('#normalMenuToggle').click();await mp.locator('#privateAgentOpen').click();await mp.locator('#privateAgentModel option[value="test:model"]').waitFor({state:"attached"});await mp.locator('#privateAgentModel').selectOption('test:model');
  await mp.locator('#privateAgentInput').fill('telefondan');await mp.locator('#privateAgentForm button').click();await mp.locator('#privateAgentMessages').getByText('Yanıt: telefondan').waitFor();
  await mp.locator('#privateAgentClose').click();await mp.locator('#profileToggle').click();await mp.locator('#profileIdentity').getByText('tester').waitFor();
  const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAIAAAACDbGyAAAAFElEQVR4nGNkYPjPgASYGFABqXwATpMBCb/kZHAAAAAASUVORK5CYII=','base64');
  await mp.locator('#profileImage').setInputFiles({name:'avatar.png',mimeType:'image/png',buffer:png});await mp.locator('#profileImageForm button').click();await mp.getByText('Profil resmi kaydedildi.').waitFor();
  assert.deepStrictEqual(errors,[]);await mobile.close();console.log('Real Chromium desktop/mobile viewport smoke tests passed. Ollama is a fake local service.');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
