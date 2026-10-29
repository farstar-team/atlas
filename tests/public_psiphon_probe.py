"""Optional personal/authorized public-network check, separate from unit tests."""
import argparse
import asyncio
import json
from pathlib import Path
import time

from atlas.runtime import Runtime,probe
from atlas.storage import Store


async def run(state, country):
    runtime=Runtime(Store(state))
    route={'id':'public-qa-'+country.lower(),'provider':'psiphon','country':country,'provider_port':61321}
    process=await runtime.spawn(route)
    started=time.monotonic();result={'ok':False,'country':country}
    try:
        while time.monotonic()-started < 100 and process.returncode is None:
            result=await probe('socks5h://127.0.0.1:61321',country)
            if result['ok']:break
            await asyncio.sleep(4)
        print(json.dumps({'requested':country,**result,'wait_seconds':round(time.monotonic()-started,1)}),flush=True)
    finally:
        if process.returncode is None:
            process.terminate()
            try:await asyncio.wait_for(process.wait(),5)
            except asyncio.TimeoutError:process.kill();await process.wait()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--state',type=Path,required=True);parser.add_argument('--country',default='FR')
    args=parser.parse_args();asyncio.run(run(args.state,args.country))
