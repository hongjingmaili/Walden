import json
import pytest
from wechat_local import native_window,native_mirror_cli as cli
from wechat_local.native_mirror_store import MirrorError


@pytest.fixture(autouse=True)
def synthetic_private_state(tmp_path,monkeypatch):
    monkeypatch.setenv('XDG_STATE_HOME',str(tmp_path/'state'))


def test_real_window_parser_reaches_local_query_without_sync_only_namespace_fields(tmp_path,monkeypatch,capsys):
    profile=tmp_path/'synthetic.json';calls=[]
    monkeypatch.setattr(cli,'load_source_config',lambda path,physical:calls.append(('config',path,physical)) or {'synthetic':True})
    def query(config,request,*,read_mode):
        calls.append(('query',config,request,read_mode));return dict(gaps=[],messages=[],source_opens=0)
    monkeypatch.setattr(cli,'query_mirror',query)
    code=native_window.main(['--source-config',str(profile),'--read-mode','local','--contact-query','synthetic','--latest','5'])
    assert code==0 and json.loads(capsys.readouterr().out)['source_opens']==0
    assert calls[0]==('config',profile,False) and calls[1][3]=='local'
    assert calls[1][2]['target_kind']=='private' and calls[1][2]['limit']==5


def test_real_window_keeps_source_refusal_structured(tmp_path,monkeypatch,capsys):
    monkeypatch.setattr(cli,'load_source_config',lambda *_args,**_kw:{'synthetic':True})
    def refuse(*_args,**_kw):raise MirrorError('source_identity_mismatch')
    monkeypatch.setattr(cli,'query_mirror',refuse)
    code=native_window.main(['--source-config',str(tmp_path/'synthetic.json'),'--read-mode','local','--latest','5'])
    assert code==2 and json.loads(capsys.readouterr().out)['error']=='mirror_query_failed'


@pytest.mark.parametrize('flags',[
    ['--authorize-terminal-recovery'],['--expected-policy-generation','a'*32],
    ['--terminal-revoked-origin','/synthetic/origin'],['--terminal-revoked-origin-sha256','a'*64],
])
def test_sync_recovery_options_refuse_other_roles_before_loading_source(tmp_path,monkeypatch,capsys,flags):
    def forbidden(*_args,**_kw):raise AssertionError('must reject unsupported options before Source config/query')
    monkeypatch.setattr(cli,'load_source_config',forbidden)
    code=cli.main(['status','--source-config',str(tmp_path/'synthetic.json'),*flags])
    assert code==2 and json.loads(capsys.readouterr().out)['error']=='mirror_operation_failed'
