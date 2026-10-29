"""Browser proof of passive adoption and editing, with labelled fixtures."""
import argparse
import copy
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright, expect

from atlas.manager import Manager
from atlas.runtime import COUNTRIES,flag
from atlas.server import Server
from atlas.storage import Store,atomic_json,password_hash
from tests.test_core import FakeRuntime
from tests.test_existing import LinkPanel,LinkClient


class Fixtures:
    def __init__(self):
        fr=LinkClient().resource
        nl=copy.deepcopy(fr);nl.update(id='existing-nl',outbound_tag='country-nl',country='NL',name='Netherlands 🇳🇱')
        direct={'id':'existing-de','kind':'existing','provider':'existing-direct','name':'Direct','country':'',
            'outbound_tag':'direct','inbound_tags':['inbound-20867'],'enabled':True,'revision':'initial','capabilities':[]}
        warp=copy.deepcopy(direct);warp.update(id='existing-warp',provider='existing-socks',name='Cloudflare WARP',outbound_tag='warp',capabilities=['reconnect'])
        self.routes=[fr,nl,direct,warp];self.calls=[];self.saved={}
    def inventory(self):return copy.deepcopy(self.routes)
    def change(self,resource,action,data):
        self.calls.append(action)
        current=next(r for r in self.routes if r['id']==resource['id'])
        if action=='restore':
            old=self.saved[current['id']];current.update(country=old['country'],fallback_enabled=old['fallback_enabled'])
        elif action=='configure':
            self.saved[current['id']]=copy.deepcopy(current)
            current.update(country=data.get('country',current['country']),fallback_enabled=data.get('fallback_enabled',True),last_backup='fixture-backup')
        if current['country']:current['name']=COUNTRIES[current['country']]+' '+flag(current['country'])
        current['revision']='next';return copy.deepcopy(current)


class Runtime(FakeRuntime):
    def public_status(self):
        return {r['id']:{'healthy':True,'state':'primary','active':{'country':r.get('country') or 'DE',
            'ip':'203.0.113.'+str(i+1),'latency_ms':120+i*20}} for i,r in enumerate(self.routes)}


class Preview(Manager):
    def state(self):
        result=super().state();result['demo']=True;return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--chrome');args=parser.parse_args()
    output=Path('docs/images');output.mkdir(exist_ok=True,parents=True)
    with tempfile.TemporaryDirectory() as root:
        atomic_json(Path(root)/'config.json',{'password_hash':password_hash('fixture-password'),'routes':[],
            'panel':{'url':'http://127.0.0.1:1234/','token':'FIXTURE-ONLY'}})
        panel=LinkPanel()
        for gid,name in [('group-nl','Netherlands 🇳🇱'),('group-de','Germany 🇩🇪')]:
            panel.hosts.append({'groupId':gid,'inboundIds':[1],'remark':name,'port':443,'hosts':['198.51.100.1:443']})
        client=Fixtures();runtime=Runtime();manager=Preview(Store(root),runtime,lambda _:panel,client)
        server=Server(('127.0.0.1',0),manager);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with sync_playwright() as playwright:
                browser=playwright.chromium.launch(executable_path=args.chrome,headless=True) if args.chrome else playwright.chromium.launch(channel='chrome',headless=True)
                page=browser.new_page(viewport={'width':1440,'height':1050});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto('http://127.0.0.1:'+str(server.server_port));page.locator('#login-password').fill('fixture-password');page.locator('#login-form button').click()
                expect(page.locator('#import-existing')).to_be_visible();page.locator('#import-existing').click()
                expect(page.locator('#existing-import-list input')).to_have_count(4)
                response=page.request.get('http://127.0.0.1:'+str(server.server_port)+'/api/existing')
                assert 'PRIVATE' not in response.text()
                page.locator('#existing-import-confirm').click();expect(page.locator('.existing-card')).to_have_count(4)
                assert not panel.calls and not client.calls
                page.locator('#toast').evaluate('(el)=>el.hidden=true')
                page.screenshot(path=str(output/'existing-desktop.png'),full_page=True)
                page.locator('[data-action=existing-edit][data-id=existing-fixture]').click()
                page.locator('#existing-country').select_option('US');page.locator('#existing-fallback').uncheck()
                page.locator('#existing-edit-form button[type=submit]').click();page.locator('#confirm-yes').click()
                expect(page.locator('#existing-edit-dialog')).not_to_be_visible()
                assert panel.hosts[0]['remark']=='United States 🇺🇸';assert panel.hosts[0]['muxParams']=={'keep':'unchanged'}
                assert not panel.calls
                page.locator('[data-action=existing-edit][data-id=existing-fixture]').click();page.locator('#existing-restore').click();page.locator('#confirm-yes').click()
                expect(page.locator('#existing-edit-dialog')).not_to_be_visible();assert panel.hosts[0]['remark']=='France 🇫🇷'
                before=len(client.calls);page.locator('[data-action=existing-reconnect][data-id=existing-warp]').click()
                assert 'UDP' in page.locator('#confirm-text').inner_text();page.locator('#confirm-no').click();assert len(client.calls)==before
                page.locator('[data-action=host][data-id=existing-fixture]').click()
                expect(page.locator('#existing-host-instructions')).to_be_visible();expect(page.locator('#new-host-instructions')).not_to_be_visible()
                page.locator('#host-dialog .close-dialog').click()
                page.set_viewport_size({'width':390,'height':844});page.locator('#toast').evaluate('(el)=>el.hidden=true')
                assert page.locator('body').evaluate('(el)=>el.scrollWidth<=innerWidth')
                page.screenshot(path=str(output/'existing-mobile.png'),full_page=True)
                assert not errors,errors;browser.close()
                print('Existing UI: discovery, credential redaction, no-restart adoption, country/fallback edit, Host preservation, rollback and WARP warning passed.')
        finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':main()
