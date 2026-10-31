"""Scoped native Host CRUD; no client, inbound or Xray-template writes."""
import copy
import ipaddress
import json
import re
import secrets
import urllib.parse

from .panel import PanelError
from .storage import atomic_json, fingerprint


FIELDS = {'remark', 'hosts', 'port', 'inboundIds', 'security', 'sni', 'hostHeader', 'path', 'isDisabled'}


def endpoint(value, default_port=0):
    if not isinstance(value, str) or not value or len(value) > 300 or any(c.isspace() for c in value):
        raise ValueError('آدرس Host باید IP یا دامنه باشد؛ هر آدرس را در یک خط بنویسید.')
    if '://' in value or any(c in value for c in '?#@\\'):
        raise ValueError('آدرس Host نباید لینک یا شامل رمز باشد؛ فقط دامنه یا IP و پورت اختیاری وارد کنید.')
    if '/' in value:
        try:
            address, port = value, default_port
            if value.startswith('['):
                match = re.fullmatch(r'\[([^\]]+)\](?::([0-9]+))?', value)
                if not match:
                    raise ValueError()
                address = match.group(1); port = int(match.group(2)) if match.group(2) else default_port
            elif value.count(':') == 1:
                address, raw_port = value.rsplit(':', 1); port = int(raw_port)
            if not 0 <= port <= 65535:
                raise ValueError()
            return str(ipaddress.ip_network(address, strict=False)), port
        except ValueError:
            raise ValueError('رنج IP یا پورت Host معتبر نیست.') from None
    if any(c in value for c in '?#@\\'):
        raise ValueError('فقط IP یا دامنه و پورت اختیاری وارد کنید؛ لینک و رمز پذیرفته نمی‌شود.')
    if value.count(':') > 1 and not value.startswith('['):
        return str(ipaddress.IPv6Address(value)), default_port
    try:
        parsed = urllib.parse.urlsplit('//' + value)
        host, port = parsed.hostname, parsed.port
        if not host or parsed.path:
            raise ValueError()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = host.encode('idna').decode().lower()
            if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in host.rstrip('.').split('.')):
                raise ValueError()
        return host, default_port if port is None else port
    except (ValueError, UnicodeError):
        raise ValueError('IP، دامنه یا پورت Host معتبر نیست.') from None


def public(group):
    return {**{k: copy.deepcopy(group.get(k, '' if k not in ('hosts', 'inboundIds') else [])) for k in FIELDS},
        'groupId': group['groupId'], 'revision': fingerprint(group)}


def matches(actual, wanted):
    if actual is None or wanted is None:
        return actual is wanted
    for key in FIELDS:
        if key == 'port':
            continue  # Native groups report the first row's effective port.
        default = [] if key in ('hosts', 'inboundIds') else False if key in ('isHidden', 'isDisabled') else 0 if key == 'port' else ''
        left, right = actual.get(key, default), wanted.get(key, default)
        if key == 'hosts':
            left = sorted(endpoint(h, actual.get('port', 0)) for h in left)
            right = sorted(endpoint(h, wanted.get('port', 0)) for h in right)
        elif key == 'inboundIds':
            left, right = sorted(left), sorted(right)
        if left != right:
            return False
    return True


class Hosts:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store
        self.pending = self.store.root / 'hosts-pending.json'

    def read(self):
        rows = self.manager.panel().call('hosts/list')
        if rows is None:
            return []
        if not isinstance(rows, list) or any(not isinstance(x, dict) or not x.get('groupId') for x in rows):
            raise PanelError('API میزبان‌های این نسخه پشتیبانی نمی‌شود.')
        return rows

    def listing(self):
        rows = self.read()
        routes = self.store.read()['routes']
        inbounds = self.manager.panel().inbounds()
        known = {i['id'] for i in inbounds}
        # Keep bindings to disabled inbounds visible/selectable when editing;
        # the ordinary route picker intentionally returns active inbounds only.
        for iid in sorted({i for row in rows for i in row.get('inboundIds', [])} - known):
            inbounds.append({'id': iid, 'remark': 'اینباند غیرفعال #' + str(iid), 'port': 0, 'enable': False})
        return {'groups': [public(x) for x in rows], 'inbounds': inbounds,
            'pending': self.pending.exists(), 'suggestions': [
                {'route_id': r['id'], 'remark': r['name'], 'inboundIds': [r['inbound_id']], 'port': r['entry_port']}
                for r in routes if r.get('kind') != 'existing']}

    def validate(self, values):
        if not isinstance(values, dict) or set(values) - FIELDS:
            raise ValueError('فیلد تنظیم Host مجاز نیست.')
        result = copy.deepcopy(values)
        for key in ('remark', 'sni', 'hostHeader', 'path'):
            if key in result and (not isinstance(result[key], str) or len(result[key]) > (2048 if key == 'path' else 200) or any(ord(c) < 32 for c in result[key])):
                raise ValueError('متن تنظیم Host معتبر نیست.')
        if 'remark' in result and not result['remark'].strip():
            raise ValueError('برای کانفیگ یک نام بنویسید.')
        if 'port' in result and (type(result['port']) is not int or not 0 <= result['port'] <= 65535):
            raise ValueError('پورت بین صفر و ۶۵۵۳۵ باشد؛ صفر یعنی ارث‌بری از اینباند.')
        if 'hosts' in result:
            addresses = result['hosts']
            if not isinstance(addresses, list) or not 1 <= len(addresses) <= 30 or any(not isinstance(x, str) for x in addresses) or len(set(addresses)) != len(addresses):
                raise ValueError('بین یک تا ۳۰ آدرس غیرتکراری وارد کنید.')
            for address in addresses:
                endpoint(address)
        if 'inboundIds' in result:
            ids = result['inboundIds']; known = {x['id'] for x in self.manager.panel().inbounds()} | {i for row in self.read() for i in row.get('inboundIds', [])}
            if not isinstance(ids, list) or not ids or any(type(i) is not int for i in ids) or len(set(ids)) != len(ids) or set(ids) - known:
                raise ValueError('حداقل یک اینباند فعال و معتبر انتخاب کنید.')
        if 'security' in result and result['security'] not in ('same', 'tls', 'reality', 'none'):
            raise ValueError('تنظیم امنیت معتبر نیست.')
        for key in ('isHidden', 'isDisabled'):
            if key in result and type(result[key]) is not bool:
                raise ValueError('وضعیت Host معتبر نیست.')
        return result

    def finish(self, journal, rows):
        actual = next((x for x in rows if x['groupId'] == journal['id']), None)
        if not matches(actual, journal['desired']):
            raise PanelError('نتیجهٔ Host تأیید نشد؛ از بخش میزبان‌ها «بررسی عملیات نیمه‌تمام» را بزنید. درخواست خودکار تکرار نمی‌شود.')
        result = {'group': public(actual) if actual else None, 'applied': True}
        atomic_json(self.store.root / 'host-operations' / (journal['operation'] + '.json'),
            {'request': journal['request'], 'result': result})
        self.pending.unlink(missing_ok=True)
        config = self.store.read()
        linked = [r for r in config['routes'] if r.get('kind') == 'existing']
        try:
            if linked:
                self.manager._bindings(linked, self.manager.panel().inbounds(), rows)
                self.store.save(config)
        except Exception:
            self.store.event('warning', 'Host ثبت شد؛ برای تازه‌شدن ارتباط کارت‌ها، مسیرهای موجود را دوباره بررسی کنید.')
        self.store.event('host', 'تنظیم Host در پنل ثبت شد؛ اشتراک Happ را به‌روز کنید.')
        return result

    def change(self, action, data):
        with self.manager.lock:
            if action not in ('create', 'update', 'delete') or not isinstance(data, dict) or set(data) - {'operation', 'id', 'revision', 'values', 'template_id', 'template_revision'}:
                raise ValueError('درخواست Host معتبر نیست.')
            op = data.get('operation', '')
            if not isinstance(op, str) or not re.fullmatch(r'[0-9a-f]{32}', op):
                raise ValueError('شناسهٔ عملیات معتبر نیست.')
            digest = fingerprint({'action': action, 'data': data})
            cache = self.store.root / 'host-operations' / (op + '.json')
            if cache.exists():
                saved = json.loads(cache.read_text())
                if saved['request'] != digest:
                    raise ValueError('شناسهٔ عملیات قبلاً استفاده شده است.')
                return saved['result']
            if self.pending.exists() or self.manager.pending.exists():
                raise ValueError('ابتدا عملیات نیمه‌تمام را بررسی کنید.')
            rows = self.read()
            prior = next((x for x in rows if x['groupId'] == data.get('id')), None)
            if action != 'create' and (not prior or fingerprint(prior) != data.get('revision')):
                raise ValueError('Host هم‌زمان تغییر کرده یا حذف شده؛ فهرست را تازه کنید.')
            desired = None
            if action != 'delete':
                values = self.validate(data.get('values', {}))
                if action == 'create':
                    template = next((x for x in rows if x['groupId'] == data.get('template_id')), None)
                    if data.get('template_id') and (not template or fingerprint(template) != data.get('template_revision')):
                        raise ValueError('الگوی Host تغییر کرده؛ فهرست را تازه کنید.')
                    desired = copy.deepcopy(template) if template else {'security': 'same', 'randomCount': 1, 'mihomoIpVersion': 'dual'}
                    desired['groupId'] = 'atlas-' + secrets.token_hex(12)
                    desired['sortOrder'] = max((int(x.get('sortOrder', 0)) for x in rows), default=-1) + 1
                    desired.update(isDisabled=False)
                else:
                    desired = copy.deepcopy(prior)
                base_sni = desired.get('sni', '')
                desired.update(values)
                if not all(desired.get(k) for k in ('remark', 'hosts', 'inboundIds')):
                    raise ValueError('نام، آدرس و اینباند کانفیگ را مشخص کنید.')
                if 'sni' in values and values['sni'] != base_sni:
                    desired['snis'] = [values['sni']] if values['sni'] else []
                    desired['sniSharedRandom'] = False
            gid = desired['groupId'] if action == 'create' else prior['groupId']
            journal = {'action': action, 'operation': op, 'request': digest, 'id': gid, 'before': prior, 'desired': desired}
            atomic_json(self.store.root / 'host-backups' / (op + '.json'), journal)
            atomic_json(self.pending, journal)
            # A last read guards visible external edits; native API has no CAS.
            if fingerprint(self.read()) != fingerprint(rows):
                self.pending.unlink(missing_ok=True)
                raise ValueError('میزبان‌های پنل هم‌زمان تغییر کردند؛ دوباره بررسی کنید.')
            path = 'hosts/add' if action == 'create' else 'hosts/' + ('del/' if action == 'delete' else 'update/') + urllib.parse.quote(gid, safe='')
            try:
                self.manager.panel().call(path, {} if desired is None else desired, json_body=True)
            except Exception:
                # An HTTP timeout can occur after a successful database commit.
                # Read once to reconcile; never replay or erase another edit.
                try:
                    return self.finish(journal, self.read())
                except Exception:
                    raise PanelError('ثبت Host تأیید نشد؛ عملیات نگه داشته شد. از بخش میزبان‌ها وضعیت را بررسی کنید.') from None
            return self.finish(journal, self.read())

    def recover(self):
        with self.manager.lock:
            if not self.pending.exists():
                return {'applied': False}
            journal = json.loads(self.pending.read_text())
            rows = self.read()
            actual = next((x for x in rows if x['groupId'] == journal['id']), None)
            if matches(actual, journal['desired']):
                return self.finish(journal, rows)
            if matches(actual, journal['before']):
                result = {'applied': False}
                atomic_json(self.store.root / 'host-operations' / (journal['operation'] + '.json'), {'request': journal['request'], 'result': result})
                self.pending.unlink(missing_ok=True)
                return result
            raise PanelError('Host توسط ویرایش دیگری تغییر کرده؛ برای حفظ آن، بازیابی خودکار متوقف شد. تنظیم همان Host را در ثنایی بررسی کنید.')
