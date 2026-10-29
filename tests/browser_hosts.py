"""Host administration browser smoke; explicitly synthetic screenshots."""
import argparse
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import sync_playwright, expect
from atlas.manager import Manager
from atlas.server import Server
from atlas.storage import Store,atomic_json,password_hash
from tests.test_hosts import HostPanel
from tests.test_existing import LinkClient
from tests.test_core import FakeRuntime


class Preview(Manager):
    def state(self):
        state=super().state();state['demo']=True;return state


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--chrome');args=parser.parse_args()
    with tempfile.TemporaryDirectory() as root:
        atomic_json(Path(root)/'config.json',{'routes':[],'panel':{'url':'http://127.0.0.1:1/','token':'FIXTURE'},'password_hash':password_hash('fixture-only')})
        panel=HostPanel();client=LinkClient();client.resource['engine_available']=True
        manager=Preview(Store(root),FakeRuntime(),lambda _:panel,client);manager.import_existing(['existing-fixture'])
        server=Server(('127.0.0.1',0),manager);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(executable_path=args.chrome,headless=True) if args.chrome else pw.chromium.launch(channel='chrome',headless=True)
                page=browser.new_page(viewport={'width':1440,'height':1050});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                base='http://127.0.0.1:'+str(server.server_port)
                assert page.request.get(base+'/api/hosts').status==401
                page.goto(base);page.locator('#login-password').fill('fixture-only');page.locator('#login-form button').click()
                page.locator('[data-view=settings]').click();expect(page.locator('#engine-state')).to_contain_text('برای مسیرهای فعلی لازم نیست')
                page.locator('[data-view=hosts]').click();expect(page.locator('.host-card')).to_have_count(1)
                page.locator('#host-add').click();page.locator('#host-name').fill('Direct France 🇫🇷')
                page.locator('#host-addresses').fill('198.51.100.10');page.locator('#host-port').fill('443');page.locator('#host-inbounds').select_option('1')
                page.locator('#host-edit-form button[type=submit]').click();expect(page.locator('.host-card')).to_have_count(2)
                page.locator('[data-host-action=edit]').first.click();page.locator('#host-name').fill('IR1 France 🇫🇷')
                page.locator('#host-edit-form button[type=submit]').click();expect(page.locator('#host-edit-dialog')).not_to_be_visible()
                assert panel.hosts[0]['muxParams']=={'keep':'unchanged'} and panel.hosts[0]['snis']==['one.example.com','two.example.com']
                page.locator('[data-host-action=clone]').first.click();page.locator('#host-name').fill('Backup France 🇫🇷')
                page.locator('#host-edit-form button[type=submit]').click();expect(page.locator('.host-card')).to_have_count(3)
                assert panel.hosts[-1]['sockoptParams']=='{"keep":true}' and panel.hosts[-1]['sniSharedRandom']
                page.locator('#toast').evaluate('(el)=>el.hidden=true');page.screenshot(path='docs/images/hosts-desktop.png',full_page=True)
                page.locator('[data-host-action=edit]').first.click();page.screenshot(path='docs/images/host-editor.png',full_page=True)
                page.locator('#host-edit-dialog .close-dialog').click()
                page.locator('[data-host-action=delete]').last.click();page.locator('#confirm-no').click();expect(page.locator('.host-card')).to_have_count(3)
                page.locator('[data-host-action=delete]').last.click();page.locator('#confirm-yes').click();expect(page.locator('.host-card')).to_have_count(2)
                page.set_viewport_size({'width':390,'height':844});page.locator('#toast').evaluate('(el)=>el.hidden=true')
                assert page.locator('body').evaluate('(el)=>el.scrollWidth<=innerWidth');page.screenshot(path='docs/images/hosts-mobile.png',full_page=True)
                page.locator('[data-host-action=edit]').first.click();assert page.locator('#host-edit-dialog').evaluate('(el)=>el.scrollWidth<=el.clientWidth')
                assert not errors,errors;assert not panel.calls;browser.close()
                print('Host UI: authenticated CRUD, clone, advanced field preservation, shared engine message, confirmation and mobile layout passed.')
        finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':main()
