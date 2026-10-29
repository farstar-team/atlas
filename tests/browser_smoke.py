"""UI interaction and visual evidence with explicitly labelled fixture data.

Optional development dependency: pip install playwright (use installed Chrome).
Never ships or starts a fake provider in the installed application.
"""
import argparse
import copy
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright, expect

from atlas.manager import Manager
from atlas.server import Server
from atlas.storage import Store,atomic_json,password_hash
from tests.test_core import FakePanel,FakeRuntime,route


class PreviewManager(Manager):
    def state(self):
        result=super().state();result['demo']=True;return result


class PreviewRuntime(FakeRuntime):
    def public_status(self):
        return {r['id']:{'healthy':True,'state':'primary', 'active':{'ip':'203.0.113.'+str(i+1),
            'country':r['country'],'latency_ms':(146,183,210)[i%3]}} for i,r in enumerate(self.routes)}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--chrome');parser.add_argument('--output',type=Path,default=Path('docs/images'))
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        runtime=PreviewRuntime();panel=FakePanel()
        atomic_json(Path(temp)/'config.json',{'routes':[],'panel':{'url':'http://127.0.0.1:1234/','token':'FIXTURE-ONLY'},
            'password_hash':password_hash('fixture-preview-password'),'listen':'127.0.0.1','port':9786})
        manager=PreviewManager(Store(temp),runtime,lambda _:panel)
        for i,code in enumerate(('FR','NL','DE')):
            item=route('fixture'+str(i));item.update(country=code,slot=i+1,source_ip='127.77.0.'+str(i+1),
                socks_port=61101+i,provider_port=61201+i,entry_port=20001+i,name={'FR':'France 🇫🇷','NL':'Netherlands 🇳🇱','DE':'Germany 🇩🇪'}[code])
            config=manager.store.read();config['routes'].append(item);manager.store.save(config)
        runtime.routes=manager.store.read()['routes']
        server=Server(('127.0.0.1',0),manager);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with sync_playwright() as playwright:
                browser=playwright.chromium.launch(executable_path=args.chrome,headless=True) if args.chrome else playwright.chromium.launch(channel='chrome',headless=True)
                page=browser.new_page(viewport={'width':1440,'height':1050},device_scale_factor=1)
                errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                page.goto('http://127.0.0.1:'+str(server.server_port));page.locator('#login').wait_for(state='visible')
                page.locator('#login-password').fill('fixture-preview-password');page.locator('#login-form button').click()
                page.locator('.route-card').first.wait_for();page.locator('#preview-banner').wait_for(state='visible')
                assert page.locator('.route-card').count()==3
                assert page.locator('#count-healthy').inner_text()=='۳'
                assert page.locator('body').evaluate('(el)=>el.scrollWidth<=innerWidth')
                page.screenshot(path=str(args.output/'desktop.png'),full_page=True)
                page.locator('[data-view=settings]').click();page.locator('#settings').wait_for(state='visible')
                page.screenshot(path=str(args.output/'settings.png'),full_page=True)
                page.locator('[data-view=overview]').click();page.locator('#add-route').click();page.locator('#route-dialog').wait_for(state='visible')
                page.locator('#country').select_option('GB');page.locator('#proxy').fill('socks5://127.0.0.1:12080')
                page.locator('#entry-port').fill('24001');page.locator('#route-form button[type=submit]').click()
                page.locator('#host-dialog').wait_for(state='visible');assert '24001' in page.locator('#host-details').inner_text()
                page.screenshot(path=str(args.output/'host-help.png'),full_page=True)
                page.locator('#host-dialog .close-dialog').click();assert page.locator('.route-card').count()==4
                # Remove the fixture path through the actual UI and confirmation.
                page.locator('[data-action=remove]').last.click();page.locator('#confirm-yes').click()
                expect(page.locator('.route-card')).to_have_count(3)
                page.set_viewport_size({'width':390,'height':844});assert page.locator('body').evaluate('(el)=>el.scrollWidth<=innerWidth')
                page.locator('#toast').evaluate('(el)=>el.hidden=true')
                page.screenshot(path=str(args.output/'mobile.png'),full_page=True)
                page.locator('[data-view=guide]').click();page.locator('#guide').wait_for(state='visible')
                assert page.locator('body').evaluate('(el)=>el.scrollWidth<=innerWidth')
                assert not errors,errors
                browser.close();print('Browser: login, dashboard, settings, add, Host instructions, delete and mobile layout passed; no JavaScript errors.')
        finally:
            server.shutdown();server.server_close();thread.join()


if __name__=='__main__':main()
