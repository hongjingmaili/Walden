import hashlib
import json
import os
import plistlib
import pytest
from pathlib import Path
from types import SimpleNamespace

from wechat_local import native_follow as follow,native_schedule as schedule,source_setup
from wechat_local.native_follow_policy import Store,digest,encoded


@pytest.mark.parametrize('change,result_kind,timing',[(change,kind,'late') for change in ['spawn','completion','continuous','leader','context','deadline','operation','app_epoch','source_conflict','global_nonzero','invalid_partial','os_owner','source_config','revoked','time_budget'] for kind in ('success','partial')]+[('spawn','unstarted','late')]+[(change,kind,'early') for change in ('spawn','completion','same_bytes','media_completion','media_failed') for kind in ('success','partial')]+[(change,kind,'late') for change in ('media_completion','media_failed') for kind in ('success','partial')]+[('cleanup_deadline','success','early'),('cleanup_future','success','early')])
def test_actual_listener_rechecks_atomic_worker_status_before_stopping_owned_source(tmp_path,monkeypatch,change,result_kind,timing):
    store=Store(tmp_path/'follow',create=True);generation='1'*32
    config={'synthetic':'source','message_root':str(tmp_path/'source')}
    profile=tmp_path/'profile';profile.write_bytes(encoded(config));profile.chmod(0o600)
    policy=dict(label='org.walden.synthetic',executable='/synthetic/sync',generation=generation,
                agent_path=str(tmp_path/'agents/listener.plist'),environment={},snapshot=str(profile),profile_path=str(profile),
                store_root=str(store.root),source_signature=digest(config),
                settings=dict(executable='/synthetic/app',poll=2,drain=30,drain_interval=5,interval=30,round=30,segment=180))
    if change=='cleanup_deadline':policy['settings']['segment']=1
    policy['policy_path']=str(store.path('policy.'+generation+'.json'));path=store.immutable('policy.'+generation+'.json',policy)
    store.atomic('intent.json',dict(enabled=True,generation=generation))
    context=dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=1)
    listener=dict(pid=os.getpid(),uid=os.getuid(),pgid=os.getpid(),start=[1,2])
    child=dict(pid=100,uid=os.getuid(),pgid=100,start=[3,4])
    kernel=SimpleNamespace(identity=lambda pid:listener if pid==listener['pid'] else child,
        require_own_leader=lambda _:None,same_generation=lambda a,b:a==b,
        group_members=lambda *_:[listener],drained=lambda _:False)
    run=SimpleNamespace(context=context,process=kernel,pid=lambda target:listener['pid'] if target.endswith(policy['label']) else child['pid'])
    epoch=dict(pid=200,uid=os.getuid(),start=[5,6]);stops=[];observed=[];changed=[];status_reads=[]
    monkeypatch.setattr(follow,'_observe',lambda *_:'owned');monkeypatch.setattr(follow,'_material',lambda _:'installed')
    monkeypatch.setattr(follow,'load_source_config',lambda *_,**__:config)
    monkeypatch.setattr(source_setup,'load_source_config',lambda *_,**__:config)
    monkeypatch.setattr(follow,'_writer_state',lambda _:'free')
    monkeypatch.setattr(schedule,'_writer_state',lambda _:'free');monkeypatch.setattr(schedule,'_observe',lambda *_:'unknown' if change=='os_owner' and changed else 'owned')
    if change=='time_budget':
        ticks=iter(range(0,1000,3));monkeypatch.setattr(follow.time,'monotonic',lambda:next(ticks))
    monkeypatch.setattr(follow,'_retire_stopped_worker',lambda *_,**__:1)
    def stop(*_):
        if store.read('intent.json')['enabled']:
            stops.append('premature');store.atomic('intent.json',dict(enabled=False,generation=generation))
        return True
    monkeypatch.setattr(follow,'_stop_segment',stop)
    def configure(_config,_snapshot,_exe,services,_enable,*,runner,follow_grant,prepared):
        operation='4'*32;label=schedule._schedule_label(config,follow_grant);record_path=services/(label+'.owned')
        argv=schedule._follow_args([policy['executable'],'bounded','--source-config',str(profile),'--operation-record',str(record_path)],follow_grant)
        payload=dict(Label=label,ProgramArguments=argv+['--operation-token',operation],EnvironmentVariables=dict(WALDEN_OPERATION_ID=operation))
        plist=record_path.with_suffix('.plist');plist.write_bytes(plistlib.dumps(payload));plist.chmod(0o600)
        raw,identity=schedule._read(plist)
        record=dict(operation=operation,os_context=context,preflight='absent',plist_identity=identity,
                    plist_sha256=hashlib.sha256(raw).hexdigest(),config_sha256=schedule._config_facts(config),
                    target='/'.join((context['domain'],str(context['uid']),'1',label)),deadline=follow_grant['deadline'],
                    follow_grant=follow_grant['path'],follow_grant_sha256=follow_grant['sha256'],interval_seconds=30)
        record_path.write_bytes(encoded(record));record_path.chmod(0o600)
        done=dict(operation=operation,attempt=1,exit_code=0,completed_at_ns=1,observation=dict(complete=False,observation_id='5'*32,watermarks=[]),source_conflicts=[])
        runtime=dict(operation=operation,os_context=context,leader=child,status='running',attempts=1,last_completed=done,
                     deadline=follow_grant['deadline'],child_pid=201,child_exit=0)
        if result_kind=='partial':
            done.update(exit_code=1,observation=None,failure_class='partial_retryable',partial_source=dict(successful_shards=1,retrying_shards=1))
            runtime.update(child_exit=1,source_schedule=dict(mode='normal'))
        elif result_kind=='unstarted':
            runtime.update(attempts=0,last_completed=None,child_exit=None)
        record_path.with_suffix('.runtime').write_bytes(encoded(runtime));record_path.with_suffix('.runtime').chmod(0o600)
        prepared(dict(operation=operation,record=str(record_path),grant=follow_grant,os_context=context))
        return plist
    monkeypatch.setattr(follow,'configure',configure)
    original=schedule._read
    def read(file):
        file=Path(file)
        if file.suffix=='.runtime':
            status_reads.append(str(file))
            trigger=1 if timing=='early' else 2
            if len(status_reads)==trigger or change=='continuous' and len(status_reads)%2==0:
                prior=original(file) if timing=='early' else None
                v=json.loads(file.read_bytes())
                if change in ('cleanup_deadline','cleanup_future'):
                    if change=='cleanup_deadline':
                        import time
                        time.sleep(1.05)
                    v.update(status='stopping',stop_reason='deadline',group_drained=False,registration_absent=False,
                             cleanup_observation=dict(remove_accepted=True,registration='owned'))
                elif change in ('media_completion','media_failed'):
                    from wechat_local.native_background import _record_media_exit
                    _record_media_exit(v,0 if change=='media_completion' else 2)
                elif change!='same_bytes':
                    v.update(attempts=v['attempts']+1,child_pid=202,attempt_record=dict(attempt=v['attempts']+1,phase='spawned'))
                if change=='completion':v['last_completed'].update(attempt=2,completed_at_ns=2)
                elif change=='leader':v['leader']['start']=[9,9]
                elif change=='context':v['os_context']['security_session']=2
                elif change=='deadline':v['deadline']['wall_until']+=1
                elif change=='operation':v['operation']='9'*32
                elif change=='app_epoch':v['app_epoch']=dict(pid=999,start=[9,9])
                elif change=='source_conflict':v['last_completed'].update(exit_code=2,source_conflicts=['source_identity_mismatch'])
                elif change=='global_nonzero':v['last_completed'].update(exit_code=2,failure_class='retryable');v['child_exit']=2
                elif change=='invalid_partial':v['last_completed'].update(exit_code=1,failure_class='partial_retryable',partial_source=dict(successful_shards=0,retrying_shards=1));v['child_exit']=1
                elif change=='source_config':profile.write_bytes(encoded(dict(config,unapproved=True)))
                elif change=='revoked':store.atomic('intent.json',dict(enabled=False,generation=generation))
                staged=file.with_suffix('.replacement');staged.write_bytes(encoded(v));staged.chmod(0o600);os.replace(staged,file);changed.append(True)
                if prior is not None:return prior
        return original(file)
    monkeypatch.setattr(schedule,'_read',read)
    class Events:
        identity=[1,2];generation=1
        def wait(self,_):
            state=follow._runtime(store)
            if changed:
                observed.append(dict(state=state['state'],admission=state['admission']))
                if change=='cleanup_deadline':
                    from wechat_local import native_follow_grant as grants
                    grant=store.read('grant.'+state['grant_nonce']+'.json')
                    api=SimpleNamespace(context=context,get=lambda _:dict(ProgramArguments=state['listener_argv'],PID=listener['pid']))
                    with pytest.raises(follow.MirrorError,match='schedule_deadline_expired'):
                        grants.validate(grant,api=api,process=kernel,check_application=False)
                if change=='revoked':
                    from wechat_local import native_follow_grant as grants
                    grant=store.read('grant.'+state['grant_nonce']+'.json')
                    with pytest.raises(follow.MirrorError,match='follow_revoked'):
                        grants.validate(grant,process=kernel,check_application=False)
                store.atomic('intent.json',dict(enabled=False,generation=generation))
            return 1
        def close(self):pass
    follow.run_listener(path,digest(policy),operation_token=generation,run=run,process=kernel,sleep=lambda _:None,
                        app_observer=lambda _:dict(state='running',epoch=epoch),event_factory=lambda _:Events())
    assert changed and len(status_reads)<=8
    events=follow.worker_observations(follow._runtime(store))
    assert events and len(events)<=8
    assert all(set(event)=={'operation','at_ns','reason','stage','attempt','retries','recovered','status_before','status_after','runtime_file_replaced','stop_context'} for event in events)
    if change=='media_failed':
        with Path(status_reads[-1]).open() as file:
            value=json.load(file)
        assert value['media_child_exit']==2 and value['media_failed_exits']['2']==1
    if change in ('spawn','completion','same_bytes','media_completion','media_failed','cleanup_deadline'):
        assert any(event['reason'] in ('runtime_ordinary_change','runtime_cleanup_change') and event['recovered'] for event in events)
    if change in ('spawn','completion','same_bytes','media_completion','media_failed','cleanup_deadline'):
        assert stops==[]
        assert observed==[dict(state='partial_source' if result_kind=='partial' else 'starting' if result_kind=='unstarted' else 'catching_up',admission=True)]
        assert len(status_reads)==4
    elif change=='revoked':
        assert stops==[]
        assert len(status_reads)==4
    elif change in ('os_owner','source_config'):
        assert stops==[]
        assert observed==[dict(state='unknown',admission=False)]
        assert len(status_reads)==2
    else:
        assert stops==['premature']
        assert observed==[]
        assert len(status_reads)==(6 if change=='continuous' else 2)
