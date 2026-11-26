import json
import pytest

def test_actual_listener_partial_status_and_deadline_keep_admission_but_reject_revocation(tmp_path,monkeypatch,capsys):
    import os
    from types import SimpleNamespace
    from wechat_local import native_follow as follow,native_follow_grant as grants,source_setup,native_follow_app,public_service
    from wechat_local.native_follow_policy import Store,digest,encoded
    store=Store(tmp_path/'follow',create=True);generation='1'*32
    config=dict(message_root=str(tmp_path/'synthetic-source'))
    policy=dict(label='org.walden.synthetic',executable='/synthetic/sync',generation=generation,
                agent_path=str(tmp_path/'agents/synthetic.plist'),
                environment={},snapshot=str(tmp_path/'snapshot'),profile_path=str(tmp_path/'profile'),
                store_root=str(store.root),source_signature=digest(config),
                settings=dict(executable='/synthetic/app',poll=2,drain=30,drain_interval=5,interval=30,round=30,segment=180))
    policy['policy_path']=str(store.path('policy.'+generation+'.json'))
    path=store.immutable('policy.'+generation+'.json',policy)
    store.atomic('intent.json',dict(enabled=True,generation=generation))
    leader=dict(pid=os.getpid(),uid=os.getuid(),pgid=os.getpid(),start=[1,2])
    context=dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=1)
    run=SimpleNamespace(context=context,pid=lambda _:leader['pid'])
    kernel=SimpleNamespace(identity=lambda _:leader,require_own_leader=lambda _:None,
                           same_generation=lambda a,b:a==b,group_members=lambda *_:[leader])
    epoch=dict(pid=100,uid=os.getuid(),start=[1,1]);observations=[]
    monkeypatch.setattr(follow,'_observe',lambda *_:'owned')
    monkeypatch.setattr(follow,'_material',lambda _:'installed')
    monkeypatch.setattr(follow,'load_source_config',lambda *_,**__:config)
    monkeypatch.setattr(source_setup,'load_source_config',lambda *_,**__:config)
    monkeypatch.setattr(follow,'_writer_state',lambda _:'free')
    monkeypatch.setattr(follow,'_stop_segment',lambda *_:True)
    monkeypatch.setattr(follow,'_retire_stopped_worker',lambda *_,**__:1)
    monkeypatch.setattr(follow,'_settle_cleanup_handoff',lambda *args:args[-1])
    monkeypatch.setattr(follow,'_segment_status',lambda *_:dict(registration='owned',stop_confirmed=False,writer_lock='busy',gaps=[]))
    def configure(_config,_snapshot,_exe,services,_enable,*,runner,follow_grant,prepared):
        operation='4'*32;plist=services/(follow._schedule_label(config,follow_grant)+'.plist')
        prepared(dict(operation=operation,record=str(plist.with_suffix('.owned')),grant=follow_grant,os_context=context))
        done=dict(operation=operation,attempt=1,exit_code=1,failure_class='partial_retryable',
                  partial_source=dict(successful_shards=1,retrying_shards=1),source_conflicts=[],observation=None)
        for suffix,value in (('.owned',dict(operation=operation)),('.runtime',dict(operation=operation,attempts=1,last_completed=done))):
            file=plist.with_suffix(suffix);file.write_bytes(encoded(value));file.chmod(0o600)
        return plist
    monkeypatch.setattr(follow,'configure',configure)
    class Events:
        identity=[1,2];generation=1
        def wait(self,_):
            state=follow._runtime(store)
            if state.get('state')=='partial_source':
                grant=store.read('grant.'+state['grant_nonce']+'.json')
                api=SimpleNamespace(context=context,get=lambda _:dict(ProgramArguments=state['listener_argv'],PID=leader['pid']))
                monkeypatch.setattr(public_service,'PublicService',lambda:api)
                monkeypatch.setattr(grants.kernel,'identity',lambda _:leader)
                monkeypatch.setattr(grants.kernel,'same_generation',lambda a,b:a==b)
                monkeypatch.setattr(native_follow_app,'matches',lambda *_:True)
                monkeypatch.setattr(follow,'observe',lambda _:dict(state='running',epoch=epoch))
                deadline=grants.FollowDeadline(grant['deadline'],grant)
                deadline.check()
                status=follow.status(tmp_path/'profile',run=run,root=store.root)
                assert status['state']=='partial_source'
                assert status['gaps']==['follow_shard_retry_pending']
                assert status['observed_catchup_complete'] is not True
                assert status['round']['last_completed']['exit_code']==1
                from wechat_local import native_mirror_cli
                monkeypatch.setattr(follow,'LaunchctlTransport',lambda:run)
                monkeypatch.setattr(follow,'default_root',lambda _:store.root)
                assert native_mirror_cli.main(['follow-status','--source-config',str(tmp_path/'profile')])==1
                emitted=json.loads(capsys.readouterr().out)
                assert emitted['state']=='partial_source' and emitted['gaps']==['follow_shard_retry_pending']
                assert emitted['round']['last_completed']['exit_code']==1
                observations.append(dict(admission=state['admission'],state=state['state'],validation_failure=None))
                with monkeypatch.context() as no_app:
                    no_app.setattr(native_follow_app,'matches',lambda *_:False)
                    with pytest.raises(follow.MirrorError,match='follow_app_inactive'):deadline.check()
                config['unapproved_source_change']=True
                try:
                    with pytest.raises(follow.MirrorError,match='follow_source_conflict'):deadline.check()
                finally:config.pop('unapproved_source_change')
                store.atomic('intent.json',dict(enabled=False,generation=generation))
                with pytest.raises(follow.MirrorError,match='follow_revoked'):deadline.check()
            return 1
        def close(self):pass
    follow.run_listener(path,digest(policy),operation_token=generation,run=run,process=kernel,
                        sleep=lambda _:None,app_observer=lambda _:dict(state='running',epoch=epoch),event_factory=lambda _:Events())
    print(json.dumps(dict(listener_partial_observations=observations)))
    assert len(observations)==1 and observations[0]['admission'] is True and observations[0]['validation_failure'] is None
