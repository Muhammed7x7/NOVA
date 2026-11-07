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
        with patch.object(self.app,'_mavi_lab_container_state',return_value={'running':True,'boundary_safe':True,'workspace_bytes':0}), patch.object(self.app.subprocess,'run',return_value=CompletedProcess([],0,'ok','')) as run:
            result=self.app.mavi_repo_lab_command('echo hello','.')
        self.assertEqual(result['output'],'ok')
        args=run.call_args.args[0]
        self.assertEqual(args[:2],['docker','exec']);self.assertIn(self.app.MAVI_LAB_CONTAINER,args)
        self.assertIn('--user',args);self.assertIn('--workdir',args);self.assertEqual(args[args.index('--workdir')+1],'/workspace')
        self.assertFalse(run.call_args.kwargs['shell'])

    def test_lab_refuses_stopped_and_over_limit(self):
        for state in [{'running':False,'workspace_bytes':0},{'running':True,'boundary_safe':False,'workspace_bytes':0},{'running':True,'boundary_safe':True,'workspace_bytes':self.app.MAVI_LAB_WORKSPACE_LIMIT}]:
            with patch.object(self.app,'_mavi_lab_container_state',return_value=state), self.assertRaises(ValueError):
                self.app.mavi_repo_lab_command('echo hello','.')

    def test_container_inspection_fails_closed_on_boundary_drift(self):
        import json
        from subprocess import CompletedProcess
        workspace=str(self.app.MAVIORKIDE_ROOT)
        entry={'State':{'Running':True},'HostConfig':{'Privileged':False,'ReadonlyRootfs':True,'Memory':3221225472,'PidsLimit':256,'SecurityOpt':['no-new-privileges:true'],'CapDrop':['ALL'],'NetworkMode':'bridge','PidMode':'','IpcMode':'private'},'Mounts':[{'Type':'bind','Source':workspace,'Destination':'/workspace'}]}
        def inspect():
            with patch.object(self.app.subprocess,'run',return_value=CompletedProcess([],0,json.dumps([entry]),'')):
                return self.app._mavi_lab_container_state()
        self.assertTrue(inspect()['boundary_safe'])
        for field,value in [('Privileged',True),('ReadonlyRootfs',False),('CapDrop',[]),('CapAdd',['SYS_ADMIN']),('NetworkMode','host'),('IpcMode','host'),('PidMode','host'),('Devices',[{'PathOnHost':'/dev/sda'}])]:
            old=entry['HostConfig'].get(field);entry['HostConfig'][field]=value
            self.assertFalse(inspect()['boundary_safe'],field);entry['HostConfig'][field]=old
        entry['Mounts'].append({'Type':'bind','Source':'/var/run/docker.sock','Destination':'/var/run/docker.sock'})
        self.assertFalse(inspect()['boundary_safe'])
        with patch.object(self.app.subprocess,'run',side_effect=OSError('not available')):
            self.assertFalse(self.app._mavi_lab_container_state()['boundary_safe'])
