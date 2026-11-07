"""Exercise the real local HTTP wire using a fake service, not an Ollama installation."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from access_hub_next import chat

class FakeOllama(BaseHTTPRequestHandler):
    requests = []
    def log_message(self,*args): pass
    def do_POST(self):
        raw=self.rfile.read(int(self.headers['Content-Length']))
        body=json.loads(raw);self.__class__.requests.append((self.path,body))
        output=json.dumps({'message':{'role':'assistant','content':'fake local response'}}).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(output)));self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(output)

class OllamaWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try: cls.server=ThreadingHTTPServer(('127.0.0.1',11434),FakeOllama)
        except OSError: raise unittest.SkipTest('loopback test port 11434 is already in use')
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls): cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def test_wire_format_and_response(self):
        FakeOllama.requests.clear()
        result=chat.request_ollama('model:test',[{'role':'user','content':'Merhaba'}],'Yerel talimat')
        self.assertEqual(result,'fake local response')
        path,data=FakeOllama.requests[0];self.assertEqual(path,'/api/chat');self.assertEqual(data['model'],'model:test');self.assertFalse(data['stream'])
        self.assertEqual(data['messages'],[{'role':'system','content':'Yerel talimat'},{'role':'user','content':'Merhaba'}])
