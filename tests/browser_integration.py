"""Real Chromium UI test against temporary SQLite and a fake local Ollama service.

Needs npm devDependencies and Chromium's system NSS/NSPR libraries. Never connects
or writes to the real server. Run separately from unittest discovery.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

class FakeOllama(BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def _send(self,data):
        raw=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        if self.path == '/api/tags': self._send({'models':[{'name':'test:model','size':42}]})
        else: self.send_error(404)
    def do_POST(self):
        if self.path != '/api/chat': self.send_error(404);return
        req=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self._send({'message':{'role':'assistant','content':'Yanıt: '+req['messages'][-1]['content']}})

def main():
    with tempfile.TemporaryDirectory() as root:
        os.environ['APP_DATA_DIR']=root+'/data';os.environ['MAVIORKIDE_ROOT']=root+'/workspace';os.environ['INITIAL_ADMIN_PASSWORD']='temporary-password-123'
        from access_hub_next import app,rbac,models
        app.init_db()
        user=app.admin_create_user({'role':'standard','username':'tester','display_name':'Test User','credential':'tester-password'})
        with app.connect() as db:
            role=rbac.create_role(db,1,{'key':'agent-user','display_name':'Agent User'})
            rbac.set_role_permissions(db,1,role,['portal.view','agent.chat','agent.history','agent.models.use'])
            rbac.link(db,1,'user-role',user['id'],role,True)
            models.configure(db,1,{'tag':'test:model','display_name':'Test model','active':True,'default_model':True,'role_ids':[role]}, {'test:model'})
        try: fake=ThreadingHTTPServer(('127.0.0.1',11434),FakeOllama)
        except OSError as exc: raise SystemExit('Fake Ollama cannot bind 127.0.0.1:11434; refusing to contact an existing service') from exc
        web=ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        threads=[threading.Thread(target=x.serve_forever,daemon=True) for x in (fake,web)]
        for t in threads:t.start()
        try:
            env=os.environ.copy();env['NOVA_TEST_URL']=f'http://127.0.0.1:{web.server_port}'
            subprocess.run(['node','tests/browser_integration.cjs'],cwd=ROOT,env=env,check=True,timeout=90)
        finally:
            for s in (web,fake):s.shutdown();s.server_close()
            for t in threads:t.join()
if __name__=='__main__':main()
