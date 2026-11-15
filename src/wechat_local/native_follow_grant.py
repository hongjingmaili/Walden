"""Finite follow grants: fixed policy, current instance, active epoch or exit drain."""
import hashlib
import json
from pathlib import Path
from .native_deadline import Deadline
from .native_mirror_store import MirrorError
from .native_schedule import _read
from .native_follow_policy import Store,digest
from . import native_process as kernel


def load(path,sha256):
    path=Path(path).absolute();raw,_=_read(path)
    if hashlib.sha256(raw).hexdigest()!=sha256:raise MirrorError('follow_grant_unknown')
    grant=json.loads(raw)
    if grant.get('kind') not in ('active','drain','request','directory_probe','source_recovery') or path.parent!=Path(grant.get('store_root','')):
        raise MirrorError('follow_grant_unknown')
    if path.name!='grant.'+grant.get('nonce','')+'.json':raise MirrorError('follow_grant_unknown')
    Deadline(grant['deadline']).check()
    return grant


def _enabled_intent(store,grant):
    intent=store.read('intent.json')
    if (type(intent) is not dict or intent.get('enabled') is not True
            or intent.get('generation')!=grant['policy_generation']):
        raise MirrorError('follow_revoked')


def _instance_runtime(store,grant):
    current=store.read('current.json')
    if not current or current.get('nonce')!=grant['instance_nonce']:raise MirrorError('follow_instance_changed')
    runtime=store.read('instance.'+grant['instance_nonce']+'.json')
    if (not runtime or runtime.get('operation')!=grant['instance_nonce'] or runtime.get('grant_nonce')!=grant['nonce']):
        raise MirrorError('follow_instance_changed')
    return runtime


def validate(grant,*,api=None,process=kernel,check_application=True):
    """No Source open here; Source's own lower guards validate its real identity."""
    if grant.get('kind')=='source_recovery':
        from .native_recovery_role import validate as recovery_validate
        return recovery_validate(grant)
    if grant.get('kind')=='directory_probe':
        from .native_directory_probe import validate as probe_validate
        return probe_validate(grant)
    if grant.get('kind')=='request':
        from .native_target_request import validate as request_validate
        return request_validate(grant)
    from .public_service import PublicService
    from .source_setup import load_source_config
    store=Store(grant['store_root'])
    _enabled_intent(store,grant)
    policy=store.read('policy.'+grant['policy_generation']+'.json')
    if (not policy or policy['source_signature']!=grant['source_sha256']
            or digest(load_source_config(Path(policy['profile_path']),physical=False))!=grant['source_sha256']):
        raise MirrorError('follow_source_conflict')
    runtime=_instance_runtime(store,grant)
    if runtime.get('admission') is not True:raise MirrorError('follow_instance_changed')
    api=api or PublicService()
    if api.context!=grant['os_context'] or runtime.get('context')!=api.context:
        raise MirrorError('follow_context_changed')
    value=api.get(policy['label'])
    leader=runtime.get('leader')
    actual=process.identity(leader['pid']) if leader else None
    if (not value or not leader or not actual or value.get('ProgramArguments')!=runtime.get('listener_argv')
            or value.get('PID')!=leader['pid'] or not process.same_generation(actual,leader)
            or actual.get('status')==5):
        raise MirrorError('follow_instance_changed')
    if grant['kind']=='active' and check_application:
        from .native_follow_app import matches
        if matches(grant['app_epoch'],policy['settings']['executable']) is not True:
            raise MirrorError('follow_app_inactive')
    elif grant['kind']=='drain':
        drain=grant.get('drain')
        if (not drain or drain['app_epoch']!=grant['app_epoch']
                or drain['policy_generation']!=grant['policy_generation']
                or drain['source_sha256']!=grant['source_sha256']):
            raise MirrorError('follow_grant_unknown')
        # No live-main requirement here: this is the explicit prior-epoch grant.
        Deadline(drain['deadline']).check()
    Deadline(grant['deadline']).check()
    return policy


class FollowDeadline(Deadline):
    def __init__(self,facts,grant,**kwargs):
        super().__init__(facts,**kwargs);self.grant=grant

    def check(self):
        super().check();validate(self.grant)

    def check_revocation(self,*,process=kernel):
        """Early refusal only; never substitutes for check() before Source.

        A live same-birth listener may briefly pause admission while switching
        a segment. That pause alone is not a new worker termination command.
        """
        grant=self.grant
        if grant.get('kind') not in ('active','drain'):return
        store=Store(grant['store_root']);_enabled_intent(store,grant)
        runtime=_instance_runtime(store,grant)
        def check_pause(value):
            if value.get('context')!=grant['os_context']:raise MirrorError('follow_context_changed')
            if value.get('admission') is not True:
                leader=value.get('leader')
                if not leader:raise MirrorError('follow_instance_changed')
                actual=process.identity(leader['pid'])
                if not process.same_generation(actual,leader) or actual.get('status')==5:
                    raise MirrorError('follow_instance_changed')
        check_pause(runtime)
        # Only authorization changes matter; ordinary round/hint/status saves
        # are concurrent and do not revoke a live segment. A pause/unpause is
        # checked again without treating it as a new termination command.
        _enabled_intent(store,grant);latest=_instance_runtime(store,grant)
        if latest.get('leader')!=runtime.get('leader'):raise MirrorError('follow_instance_changed')
        check_pause(latest)



def from_record(record,deadline):
    if not record.get('follow_grant'):return deadline
    grant=load(record['follow_grant'],record['follow_grant_sha256'])
    if grant.get('kind') in ('request','directory_probe','source_recovery') and record.get('config_sha256')!=grant.get('config_sha256'):raise MirrorError('request_snapshot_conflict')
    parent=Deadline(grant['deadline'])
    if (deadline.facts['wall_until']>parent.facts['wall_until'] or
            deadline.facts['continuous_until']>parent.facts['continuous_until']):
        raise MirrorError('follow_grant_unknown')
    return FollowDeadline(deadline.facts,grant)


from .failure_evidence import _register
_register(load,_enabled_intent,_instance_runtime,validate,FollowDeadline.check_revocation,FollowDeadline.__init__,FollowDeadline.check,from_record)
