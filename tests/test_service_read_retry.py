"""Only the public OS job provider is substituted; ownership/nonce checks stay real."""
import errno
import json
import os
from types import SimpleNamespace
from pathlib import Path
import pytest
from wechat_local import native_schedule as s
from wechat_local.native_mirror_store import MirrorError

CONTEXT=dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=1)
LABEL='org.walden.native.synthetic'
TARGET='/'.join([CONTEXT['domain'],str(CONTEXT['uid']),'1',LABEL])
ARGV=['/synthetic/sync','follow-run','--operation-token','a'*32]

class API:
 def __init__(self,outcomes):self.outcomes=list(outcomes);self.calls=0;self.context=dict(CONTEXT);self.job=None;self.submits=0;self.removes=0
 def current_context(self):return self.context
 def get(self,label):
  self.calls+=1
  item=self.outcomes.pop(0) if self.outcomes else self.job
  if isinstance(item,BaseException):raise item
  return item
 def submit(self,payload):self.submits+=1;self.job=payload
 def remove(self,*args,**kwargs):self.removes+=1

def transport(api):
 r=s.LaunchctlTransport.__new__(s.LaunchctlTransport);r.api=api;r.context=dict(CONTEXT);r.process=SimpleNamespace(identity=lambda _:None);return r

def job(argv=None):return dict(Label=LABEL,ProgramArguments=argv or ARGV,PID=12345)

@pytest.mark.parametrize('code',[errno.EINTR,errno.EAGAIN,errno.ETIMEDOUT])
@pytest.mark.parametrize('method',['observe','pid'])
def test_transient_public_read_recovers_exact_current_job(code,method,monkeypatch):
 waits=[];monkeypatch.setattr(s.time,'sleep',waits.append);a=API([OSError(code,'synthetic public read'),job()]);r=transport(a)
 if method=='observe':assert s._observe(r,TARGET,dict(ProgramArguments=ARGV))=='owned'
 else:assert r.pid(TARGET)==12345
 assert a.calls==2 and a.submits==a.removes==0 and waits==[.05]

@pytest.mark.parametrize('error',[PermissionError(errno.EACCES,'synthetic denied'),OSError(errno.EIO,'synthetic IO'),OSError('synthetic malformed field')])
def test_permission_structural_and_other_unknown_never_retry(error,monkeypatch):
 waits=[];monkeypatch.setattr(s.time,'sleep',waits.append);a=API([error,job()]);assert s._observe(transport(a),TARGET,dict(ProgramArguments=ARGV))=='unknown'
 assert a.calls==1 and not waits and a.submits==a.removes==0

def test_persistent_read_failure_is_bounded_and_no_authority(monkeypatch):
 waits=[];monkeypatch.setattr(s.time,'sleep',waits.append);a=API([OSError(errno.EAGAIN,'temporary')]*4);assert s._observe(transport(a),TARGET,dict(ProgramArguments=ARGV))=='unknown'
 assert a.calls==3 and waits==[.05,.05]and a.submits==a.removes==0

def test_recovered_read_still_rejects_changed_nonce_without_retry(monkeypatch):
 monkeypatch.setattr(s.time,'sleep',lambda _:None);a=API([OSError(errno.EAGAIN,'temporary'),job(ARGV[:-1]+['b'*32]),job()]);assert s._observe(transport(a),TARGET,dict(ProgramArguments=ARGV))=='unknown';assert a.calls==2

def test_context_change_does_not_requery_or_authorize(monkeypatch):
 monkeypatch.setattr(s.time,'sleep',lambda _:None);a=API([job()]);a.context=dict(CONTEXT,security_session=2);assert s._observe(transport(a),TARGET,dict(ProgramArguments=ARGV))=='unknown';assert a.calls==0

@pytest.mark.parametrize('recover',[True,False])
def test_configure_real_entry_transient_vs_persistent(tmp_path,monkeypatch,recover):
 monkeypatch.setattr(s.time,'sleep',lambda _:None);c=dict(account_id='synthetic',source_generation='synthetic');p=tmp_path/'profile.json';p.write_text(json.dumps(c));p.chmod(0o600);exe=tmp_path/'sync';exe.write_text('synthetic executable');exe.chmod(0o700)
 a=API([OSError(errno.EAGAIN,'synthetic OS read')]+([]if recover else[OSError(errno.EAGAIN,'synthetic OS read')]*3));r=transport(a);trace={}
 if not recover:
  with pytest.raises(MirrorError,match='schedule_state_unknown'):s.configure(c,p,exe,tmp_path/'services',True,runner=r,_prepare_trace=trace)
  assert a.submits==a.removes==0
 else:
  path=s.configure(c,p,exe,tmp_path/'services',True,runner=r,_prepare_trace=trace)
  assert path.is_file()and a.submits==1 and a.removes==0
  record=json.loads(path.with_suffix('.owned').read_text());assert record['operation']==s._argv_operation(a.job['ProgramArguments']);assert json.loads(path.with_suffix('.submission').read_text())['status']=='accepted'


def test_only_unavailable_domain_container_is_a_retryable_public_read():
 from wechat_local import public_service as p
 api=p.PublicService.__new__(p.PublicService);api.domain=None;api.copy_all=lambda _:None
 with pytest.raises(p.ServiceReadUnavailable):api._domain_job(None)


def test_typed_unavailable_recovers_but_result_shape_does_not(monkeypatch):
 from wechat_local import public_service as p
 monkeypatch.setattr(s.time,'sleep',lambda _:None)
 a=API([p.ServiceReadUnavailable('no container'),job()]);assert s._observe(transport(a),TARGET,dict(ProgramArguments=ARGV))=='owned';assert a.calls==2
 a=API([dict(Label=LABEL,ProgramArguments=['wrong']),job()]);assert s._observe(transport(a),TARGET,dict(ProgramArguments=ARGV))=='unknown';assert a.calls==1


@pytest.mark.parametrize('kind,expected',[('revoked',True),('enabled',False),('other_generation',False),('changed_policy',False)])
def test_listener_revocation_reads_bound_policy_only(tmp_path,kind,expected):
 from wechat_local import native_follow as f
 from wechat_local.native_follow_policy import Store
 store=Store(tmp_path/'follow',create=True);policy=dict(generation='a'*32,source_signature='b'*64)
 observed=dict(policy)
 if kind=='other_generation':observed['generation']='c'*32
 if kind=='changed_policy':observed['source_signature']='d'*64
 store.immutable('policy.'+observed['generation']+'.json',observed)
 store.atomic('intent.json',dict(generation=observed['generation'],enabled=kind=='enabled'))
 assert f._listener_revoked(store,policy) is expected
