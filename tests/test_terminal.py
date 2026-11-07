import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        env={'APP_DATA_DIR':self.tmp.name+'/data','MAVIORKIDE_ROOT':self.tmp.name+'/workspace','INITIAL_ADMIN_PASSWORD':'example-password-123'}
        self.env=patch.dict(os.environ,env);self.env.start()
        from access_hub_next import app
        self.app=importlib.reload(app)
        self.app.MAVIORKIDE_ROOT.mkdir(parents=True)
    def tearDown(self): self.env.stop();self.tmp.cleanup()

    def test_virtual_terminal_clamps_parent_and_blocks_host_shell(self):
        self.assertEqual(self.app.maviorkide_terminal('cd ..','.')['cwd'],'.')
        for cmd in ['sudo id','python3 --version','cat /etc/passwd; id','echo $(id)']:
            with self.subTest(cmd=cmd), self.assertRaises(ValueError): self.app.maviorkide_terminal(cmd,'.')

    def test_virtual_terminal_rejects_symlink_escape(self):
        outside=Path(self.tmp.name)/'outside.txt';outside.write_text('secret')
        (self.app.MAVIORKIDE_ROOT/'link').symlink_to(outside)
        with self.assertRaises(ValueError): self.app.maviorkide_terminal('cat link','.')

    def test_lab_uses_docker_exec_with_no_host_shell(self):
        from subprocess import CompletedProcess
        with patch.object(self.app,'_mavi_lab_container_state',return_value={'running':True,'workspace_bytes':0}), patch.object(self.app.subprocess,'run',return_value=CompletedProcess([],0,'ok','')) as run:
            result=self.app.mavi_repo_lab_command('echo hello','.')
        self.assertEqual(result['output'],'ok')
        args=run.call_args.args[0]
        self.assertEqual(args[:2],['docker','exec']);self.assertIn(self.app.MAVI_LAB_CONTAINER,args)
        self.assertIn('--user',args);self.assertIn('--workdir',args);self.assertEqual(args[args.index('--workdir')+1],'/workspace')
        self.assertFalse(run.call_args.kwargs['shell'])

    def test_lab_refuses_stopped_and_over_limit(self):
        for state in [{'running':False,'workspace_bytes':0},{'running':True,'workspace_bytes':self.app.MAVI_LAB_WORKSPACE_LIMIT}]:
            with patch.object(self.app,'_mavi_lab_container_state',return_value=state), self.assertRaises(ValueError):
                self.app.mavi_repo_lab_command('echo hello','.')
