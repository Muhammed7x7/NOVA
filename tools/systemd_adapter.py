#!/usr/bin/env python3
"""Experimental systemd-specific safety checks, not a deployment CLI."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import json
import re
import pwd
import shlex

class ServiceCheckError(RuntimeError): pass

class SystemdService:
    def __init__(self, app_dir: Path, *, runner=subprocess.run, unit='access-hub.service'):
        if unit != 'access-hub.service' and not re.fullmatch(r'nova-rehearsal-[0-9a-f]{16}\.service',unit):
            raise ServiceCheckError('Unsupported service unit')
        self.unit=unit
        self.app_dir=app_dir.resolve(strict=True)
        self._run=runner
        self.port=None
        self.mavi_root=None
    def _command(self, argv, timeout=15):
        return self._run(argv, check=True, text=True, capture_output=True, timeout=timeout)
    def _pid(self):
        result=self._command(['systemctl','--no-pager','show',self.unit,'-p','MainPID','--value'])
        value=result.stdout.strip()
        if not value.isdigit() or int(value)<=0:raise ServiceCheckError('Service PID unavailable')
        return int(value)
    def _active(self):
        result=self._command(['systemctl','--no-pager','is-active',self.unit])
        if result.stdout.strip()!='active':raise ServiceCheckError('Service is not active')
    def inspect(self):
        if os.getuid()==0:raise ServiceCheckError('Run as the service user, not root')
        self._active();pid=self._pid();proc=Path('/proc')/str(pid)
        if proc.stat().st_uid!=os.getuid():raise ServiceCheckError('Service runs as a different user')
        args=[os.fsdecode(v) for v in (proc/'cmdline').read_bytes().split(b'\0') if v]
        if len(args)!=2 or Path(args[0]).resolve()!=Path('/usr/bin/python3').resolve() or Path(args[1]).resolve()!=self.app_dir/'app.py':
            raise ServiceCheckError('Unexpected service command line')
        if (proc/'cwd').resolve()!=self.app_dir:raise ServiceCheckError('Unexpected service working directory')
        env={}
        for item in (proc/'environ').read_bytes().split(b'\0'):
            if b'=' in item:
                k,v=item.split(b'=',1);env[os.fsdecode(k)]=os.fsdecode(v)
        home=Path(env.get('HOME',str(Path.home())))
        app=Path(env.get('APP_DIR',str(home/'access-hub'))).resolve()
        data=Path(env.get('APP_DATA_DIR',str(app/'data'))).resolve()
        if app!=self.app_dir or data!=self.app_dir/'data':raise ServiceCheckError('Unexpected data directory')
        try:port=int(env.get('ACCESS_HUB_PORT','5120'))
        except ValueError as exc:raise ServiceCheckError('Invalid service port') from exc
        if not 1<=port<=65535:raise ServiceCheckError('Invalid service port')
        self.port=port
        self.mavi_root=Path(env.get('MAVIORKIDE_ROOT',str(home/'maviorkide'))).resolve()
        self._verify_listener(pid)
        return port
    def inspect_config_stopped(self, port):
        """Validate the unit even if no live process exists, for emergency rollback."""
        if os.getuid()==0:raise ServiceCheckError('Run as the service user, not root')
        if type(port) is not int or not 1<=port<=65535:raise ServiceCheckError('Invalid recorded port')
        def property_value(name):
            return self._command(['systemctl','--no-pager','--full','show',self.unit,'-p',name,'--value']).stdout.strip()
        user=property_value('User')
        try:uid=pwd.getpwnam(user).pw_uid
        except KeyError as exc:raise ServiceCheckError('Unexpected service user') from exc
        if uid!=os.getuid():raise ServiceCheckError('Service runs as a different user')
        if Path(property_value('WorkingDirectory')).resolve()!=self.app_dir:raise ServiceCheckError('Unexpected service working directory')
        command=property_value('ExecStart')
        match=re.search(r'argv\[\]=([^;]+);',command)
        if not match:raise ServiceCheckError('Unexpected service command line')
        try:args=shlex.split(match.group(1))
        except ValueError as exc:raise ServiceCheckError('Unexpected service command line') from exc
        if len(args)!=2 or Path(args[0]).resolve()!=Path('/usr/bin/python3').resolve() or Path(args[1]).resolve()!=self.app_dir/'app.py':
            raise ServiceCheckError('Unexpected service command line')
        self.port=port

    def _verify_listener(self,pid):
        # Require the *service process* to own the loopback listener; avoids
        # treating an unrelated process on the same port as a healthy restart.
        target=f'0100007F:{self.port:04X}'
        inodes=set()
        for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            fields=line.split()
            if len(fields)>9 and fields[1]==target and fields[3]=='0A':inodes.add(fields[9])
        for fd in (Path('/proc')/str(pid)/'fd').iterdir():
            try:value=os.readlink(fd)
            except OSError:continue
            if value.startswith('socket:[') and value[8:-1] in inodes:return
        raise ServiceCheckError('Loopback listener is not owned by service process')
    def stop(self):
        self._command(['sudo','-n','systemctl','stop',self.unit],timeout=30)
    def start(self):
        self._command(['sudo','-n','systemctl','start',self.unit],timeout=30)
    def healthy(self,candidate):
        if self.port is None:raise ServiceCheckError('Service preflight missing')
        deadline=time.monotonic()+20;last=None
        while time.monotonic()<deadline:
            try:
                self._active();pid=self._pid();self._verify_listener(pid)
                path='/health' if candidate else '/'
                with urllib.request.urlopen(f'http://127.0.0.1:{self.port}{path}',timeout=2) as response:
                    if response.status!=200:raise ServiceCheckError('Unexpected HTTP status')
                    if candidate and json.load(response).get('status')!='ok':raise ServiceCheckError('Unexpected health response')
                if self._pid()!=pid:raise ServiceCheckError('Service restarted during health check')
                return
            except (OSError,ValueError,ServiceCheckError,subprocess.SubprocessError,urllib.error.URLError) as exc:
                last=exc;time.sleep(.2)
        raise ServiceCheckError(f'Service health check failed: {type(last).__name__}')
