"""Private follow policy/instance files, separate from session ownership facts."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from .native_schedule import _read, _create, _sync_dir, _lock
from .native_mirror_store import MirrorError


def encoded(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def profile_id(path):
    return hashlib.sha256(str(Path(path).expanduser().absolute()).encode()).hexdigest()[:20]


def default_root(path):
    base=Path(os.environ.get('XDG_STATE_HOME',str(Path.home()/'.local/state')))
    return base/'wechat-local/follow'/profile_id(path)


class Store:
    def __init__(self,root,*,create=False):
        self.root=Path(root).absolute()
        if self.root.resolve()!=self.root:raise MirrorError('follow_state_unknown')
        if create:self.root.mkdir(parents=True,mode=0o700,exist_ok=True)
        if self.root.exists():
            info=self.root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
                raise MirrorError('follow_state_unknown')

    def path(self,name):
        if type(name) is not str or not re.fullmatch('[a-z][a-z0-9.-]{1,180}',name):
            raise MirrorError('follow_state_unknown')
        return self.root/name

    def read(self,name,*,missing=None):
        try:return json.loads(_read(self.path(name))[0])
        except FileNotFoundError:return missing

    def immutable(self,name,value):
        path=self.path(name)
        _create(path,encoded(value));_sync_dir(self.root)
        return path

    def atomic(self,name,value):
        path=self.path(name)
        try:before=_read(path)
        except FileNotFoundError:before=None
        temp=self.path('update.'+uuid.uuid4().hex+'.tmp')
        _create(temp,encoded(value))
        try:current=_read(path)
        except FileNotFoundError:current=None
        if current!=before:raise MirrorError('follow_state_unknown')
        # Both resolved endpoints belong to this already checked private root.
        if path.parent!=self.root or temp.parent!=self.root:raise MirrorError('follow_state_unknown')
        os.replace(temp,path);_sync_dir(self.root)

    def locked(self):
        return _lock(self.root)


def local_environment(home):
    values={'HOME':str(home),'PYTHONDONTWRITEBYTECODE':'1'}
    for key in ('XDG_CONFIG_HOME','XDG_DATA_HOME','XDG_CACHE_HOME','XDG_STATE_HOME'):
        if os.environ.get(key):values[key]=os.environ[key]
    return values


from .failure_evidence import _register
_register(encoded,digest,profile_id,default_root,Store.__init__,Store.path,Store.read,
          Store.immutable,Store.atomic,Store.locked,local_environment)
