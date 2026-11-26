"""Optional account-only SQLite commit witnesses. No Source authority or schema."""
import hashlib,os,sqlite3,time
from pathlib import Path
from .native_mirror_store import MirrorError
from .native_deadline import _current

# Post-COMMIT mode scalars, data_version, the commit pin, final data_version.
_COMMIT_CHECK_BYTES = 2 * 8 + 8 + 140 + 8


class WorkChanged(MirrorError):
    pass


class WorkBudgetStop(WorkChanged):
    def __init__(self,*args,budget_kind=None,limit=None,used=None,required=None):
        super().__init__(*args)
        self.budget_fact=dict(kind=budget_kind,limit=limit,used=used,required=required)


class AccountWitness:
    def __init__(self,root,budget,*,clock=time.monotonic):
        self.root=Path(root);self.budget=budget;self.clock=clock;self.expected={};self.changed=None;self.transactions=0;self.deadline=_current.get();self.registry_admit=None;self.admit_cost=0
    def remaining(self):
        value=max(0,self.budget['until']-self.clock())
        return min(value,self.deadline.remaining()) if self.deadline is not None else value
    def invalidate(self,reason):
        self.changed=reason
    def charge(self,size,lease=None):
        if self.remaining()<=0:
            self.invalidate('witness_budget');raise WorkChanged('account_work_changed')
        if lease is not None and lease.prepaid>=size:
            lease.prepaid-=size;return
        if self.remaining()<=0 or self.budget['tail_probe']['bytes']+size>1048576:
            self.invalidate('witness_budget');raise WorkChanged('account_work_changed')
        self.budget['tail_probe']['bytes']+=size
    def guard_charge(self,size,lease=None):
        # Mandatory local admission also covers terminal bookkeeping after the
        # Source body budget ends. It cannot wait beyond that body budget and
        # remains under the real parent deadline and unchanged metadata cap.
        if self.deadline is not None:self.deadline.check()
        if lease is not None and lease.prepaid>=size:
            lease.prepaid-=size;return
        if self.budget['tail_probe']['bytes']+size>1048576:
            raise WorkChanged('account_work_changed')
        self.budget['tail_probe']['bytes']+=size
    def pin(self,path,lease=None):
        from .native_scope_contract import _safe
        path=Path(path);self.charge(140,lease)
        if path.parent!=self.root:raise MirrorError('local_replaced')
        _safe(path)
        if any(os.path.lexists(str(path)+suffix) for suffix in ('-wal','-journal')):
            self.invalidate('journal');raise WorkChanged('account_work_changed')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);raw=os.read(fd,100);after=os.fstat(fd)
            fields=lambda s:[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
            if fields(before)!=fields(after) or fields(after)!=fields(path.stat()):
                self.invalidate('local_commit');raise WorkChanged('account_work_changed')
            if len(raw)!=100 or raw[:16]!=b'SQLite format 3\x00' or raw[18:20]!=b'\x01\x01':
                self.invalidate('mode');raise WorkChanged('account_work_changed')
            return dict(file=fields(after),commit=hashlib.sha256(raw).hexdigest(),counter=int.from_bytes(raw[24:28],'big'))
        finally:os.close(fd)
    def check(self,path):
        value=self.pin(path);expected=self.expected.get(str(path))
        if expected is not None and value!=expected:
            if value['file'][:2]!=expected['file'][:2]:raise MirrorError('local_replaced')
            self.invalidate('local_commit');raise WorkChanged('account_work_changed')
        return value
    def seed(self,path,pin):
        self.expected[str(path)]={key:pin[key] for key in ('file','commit','counter')}
    def before_open(self,path):
        if self.changed:raise WorkChanged('account_work_changed')
        if self.remaining()<=0 or self.budget['tail_probe']['bytes']>=1048576:
            self.invalidate('witness_budget');raise WorkChanged('account_work_changed')
        # Stop before another transaction; the final integrity checks still
        # have their own bounded cost inside the unchanged metadata cap.
        reserve=self.budget['tail_probe'].get('finish_reserve',0)
        if self.budget['tail_probe']['bytes']+476+reserve>1048576:
            raise WorkBudgetStop('account_work_budget',budget_kind='metadata_bytes',limit=1048576,used=self.budget['tail_probe']['bytes'],required=476+reserve)
        self.check(path)
    def connect(self,path):
        self.before_open(path)
        remaining=self.remaining()
        raw=sqlite3.connect(path,timeout=min(5.,remaining))
        try:return _Lease(self,Path(path),raw,owns=True)
        except BaseException:raw.close();raise
    def registry(self,path,raw):return _Lease(self,Path(path),raw,owns=False,witness=getattr(self,'registry_witness_enabled',True))
    def compare_all(self):
        for path in list(self.expected):self.check(Path(path))


class _Lease:
    def __init__(self,owner,path,raw,*,owns,witness=True):
        self.owner=owner;self.path=path;self.raw=raw;self.owns=owns;self.cursors=[];self.enabled=witness;self.publication=None;self.prepaid=0
        self.guard=not owns and owner.registry_admit is not None
        self.guard_valid=False;self.admitting=False
        self._begin(first=True)
    def __getattr__(self,name):return getattr(self.raw,name)
    @property
    def text_factory(self):return self.raw.text_factory
    @text_factory.setter
    def text_factory(self,value):self.raw.text_factory=value
    def admitted(self):
        if self.guard and not self.admitting and (not self.guard_valid or not self.raw.in_transaction):
            raise MirrorError('scope_registry_guard')
    def reserve_admission(self):
        if not self.guard:return
        self.guard_valid=False;self.admitting=True
        try:self.owner.registry_admit(self)
        finally:self.admitting=False
        self.guard_valid=True
    def execute(self,*args,**kwargs):
        self.admitted()
        value=self.raw.execute(*args,**kwargs);self.cursors.append(value);return value
    def executemany(self,*args,**kwargs):
        self.admitted()
        value=self.raw.executemany(*args,**kwargs);self.cursors.append(value);return value
    def scalar(self,sql):
        self.owner.charge(8,self);cursor=self.raw.execute(sql)
        try:
            row=cursor.fetchone()
            if row is None:raise WorkChanged('account_work_changed')
            return row[0]
        finally:cursor.close()
    def finish_statements(self):
        for cursor in self.cursors:cursor.close()
        self.cursors.clear()
    def mode(self):
        if self.scalar('PRAGMA journal_mode')!='delete' or self.scalar('PRAGMA locking_mode')!='normal':
            self.owner.invalidate('mode');raise WorkChanged('account_work_changed')
    def wait_budget(self):
        remaining=self.owner.remaining()
        self.raw.execute('PRAGMA busy_timeout='+str(int(min(5.,remaining)*1000))).close()
    def prepare_commit(self):
        if not self.prepaid:
            if self.enabled:
                self.owner.charge(_COMMIT_CHECK_BYTES+self.owner.admit_cost);self.prepaid=_COMMIT_CHECK_BYTES+self.owner.admit_cost
            elif self.guard:
                self.owner.guard_charge(self.owner.admit_cost);self.prepaid=self.owner.admit_cost
    def _begin(self,*,first=False):
        self.wait_budget();self.raw.execute('BEGIN IMMEDIATE').close()
        self.reserve_admission()
        if not self.enabled:return
        try:
            self.mode()
            self.before=self.owner.check(self.path);self.dv=self.scalar('PRAGMA data_version')
        except WorkChanged:
            if not self.guard:raise
            # Optional evidence can fail; mandatory authority remains reserved.
            self.enabled=False
            return
        if first:self.owner.expected.setdefault(str(self.path),self.before)
    def commit(self):
        _diagnostic_stage='local_commit_prepare' if self.owns else 'registry_commit_prepare'
        _diagnostic_committed=False
        if not self.enabled and not self.guard:
            _diagnostic_stage='local_commit' if self.owns else 'registry_commit'
            return self.raw.commit()
        self.admitted();self.prepare_commit()
        precommit=getattr(self.owner,'registry_precommit',None)
        if precommit is not None and self.guard:precommit(self)
        self.finish_statements();self.wait_budget();self.guard_valid=False
        _diagnostic_stage='local_commit' if self.owns else 'registry_commit'
        self.raw.commit();_diagnostic_committed=True
        _diagnostic_stage='local_commit_revalidate' if self.owns else 'registry_commit_revalidate'
        # Same connection only. Reacquire the SQLite write reservation before
        # post-commit data_version and pin reads; no foreign writer can commit
        # between those two observations. Own no-op and real commits both work.
        self.wait_budget();self.raw.execute('BEGIN IMMEDIATE').close()
        self.reserve_admission()
        if not self.enabled:return
        self.mode()
        if self.scalar('PRAGMA data_version')!=self.dv:
            self.owner.invalidate('foreign_commit');raise WorkChanged('account_work_changed')
        after=self.owner.pin(self.path,self)
        if after['file'][:2]!=self.before['file'][:2]:raise MirrorError('local_replaced')
        if (after['counter']-self.before['counter'])%(1<<32) not in (0,1):
            self.owner.invalidate('counter');raise WorkChanged('account_work_changed')
        if self.publication is not None and after['counter']!=self.publication:
            self.owner.invalidate('publication');raise WorkChanged('account_work_changed')
        self.publication=None;self.owner.expected[str(self.path)]=after;self.before=after;self.dv=self.scalar('PRAGMA data_version');self.owner.transactions+=1
    def suspend(self,*,atomic=False):
        self.finish_statements();self.raw.rollback();self.enabled=False;self.guard_valid=False;self.prepaid=0
        if self.guard and not atomic:
            self.wait_budget();self.raw.execute('BEGIN IMMEDIATE').close();self.reserve_admission()
    def __enter__(self):return self
    def __exit__(self,kind,value,tb):
        try:
            if kind is None:self.commit()
            else:
                self.finish_statements();self.raw.rollback();self.owner.invalidate('rollback')
        finally:
            if self.owns:self.raw.close()
        return False

from .failure_evidence import _register
_register(AccountWitness.charge,AccountWitness.guard_charge,AccountWitness.pin,AccountWitness.check,AccountWitness.before_open,AccountWitness.connect,
          _Lease._begin,_Lease.commit,_Lease.scalar,_Lease.mode,_Lease.__exit__,_Lease.admitted,_Lease.reserve_admission)
