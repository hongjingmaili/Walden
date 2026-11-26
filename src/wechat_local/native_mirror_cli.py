"""Installed deterministic mirror synchronization and local query commands."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import sqlite3
from pathlib import Path

from .failure_evidence import boundary, stage, error_fields, console, _register
from .confirmed_aliases import AliasError
from .native_mirror_query import query_local
from .native_schedule import configure as _configure_schedule, inspect_status as schedule_status
from .native_background import run_bounded, run_owned_once
from .native_follow_schedule import control_result, failure_details, partial_source
from .native_mirror_store import MirrorError
from .native_mirror_sync import mirror_root, sync_once
from .source_setup import load_source_config, SourceSetupError


def query_mirror(config, request, *, read_mode='local', connection_factory=None):
    sync = resolved = None
    if read_mode == 'refresh':
        if not request.get('username'):
            resolved = query_local(config, dict(request, images=False, voice_transcripts=False))
            if not resolved.get('selected_username'):
                return resolved
            request = dict(request, username=resolved['selected_username'])
        sync = sync_once(config, [request['username']], connection_factory=connection_factory, media_request=request)
    elif read_mode != 'local':
        raise MirrorError('unsupported_read_mode')
    result = sync.pop('media_window') if sync is not None and 'media_window' in sync else query_local(config, dict(request, images=False, voice_transcripts=False) if sync is not None else request)
    if resolved is not None and 'resolution' in resolved:
        result['resolution'] = resolved['resolution']
    if sync is not None:
        result['sync'] = sync
        result['gaps'] = sorted(set(result['gaps'] + sync['gaps']))
        result['freshness'] = 'stale' if result['gaps'] else 'refreshed'
    return result


def configure_schedule(config, config_path, executable, service_dir, enabled, *, runner=None, service_state=None, duration_seconds=600):
    """Use the trusted OS operation layer; profile/marker claims never prove owned.

    Legacy callback evidence is not accepted by the formal CLI. The transport
    boundary remains injectable for deterministic OS failure verification.
    """
    if service_state is not None:
        raise MirrorError('schedule_state_unknown')
    return _configure_schedule(config, config_path, executable, service_dir, enabled, runner=runner, duration_seconds=duration_seconds)


def mirror_status(config):
    from .native_scope_contract import mode,account_status
    if mode(config)=='account':return account_status(config)
    from .live_readonly import readonly_database_uri
    root = mirror_root(config, create=False)
    if any(path.is_symlink() for path in root.glob('*.db')):
        raise MirrorError('mirror_symlink')
    coverage, checked, gaps = [], [], []
    for path in sorted(root.glob('message_*.db')) + sorted(root.glob('biz_message_*.db')):
        with sqlite3.connect(readonly_database_uri(path), uri=True) as conn:
            conn.execute('PRAGMA query_only=ON')
            conn.execute('BEGIN')
            if conn.execute('SELECT * FROM __walden_binding').fetchall() != [(config['account_id'],config['source_generation'],path.name)]:
                raise MirrorError('source_identity_mismatch')
            for (payload,) in conn.execute('SELECT value FROM __walden_progress WHERE table_name LIKE ?', ('Msg_%',)):
                progress=json.loads(payload)
                coverage.append(dict(history_complete=progress['history_complete'], arbitrary_old_changes_verified=False))
                checked.append(progress['checked_at'])
                if not progress['history_complete']:
                    gaps.append('history_incomplete')
                if progress['tail'] < progress['target']:
                    gaps.append('tail_incomplete')
    status_path=root/'__walden_status.db'
    if status_path.is_file():
        with sqlite3.connect(readonly_database_uri(status_path), uri=True) as conn:
            for (payload,) in conn.execute('SELECT gaps FROM attempts'):
                gaps.extend(json.loads(payload))
    if not coverage:
        gaps.append('scope_not_copied')
    return dict(scope_count=len(config.get('mirror_scope',[])),coverage=coverage,synced_at=min(checked,default=None),synced_at_semantics='minimum_per_batch_checked_at_not_scope_completion',last_attempt_at=None,last_complete_observation_at=None,gaps=sorted(set(gaps)))


@boundary('window')
def window_main(args):
    try:
        if args.source_config is None:
            raise MirrorError('source_config_required')
        if args.include_related_groups or args.locate_related_groups or args.check_config:
            raise MirrorError('unsupported_mirror_option')
        stage('configuration')
        if (getattr(args,'authorize_current_reconcile',False)or getattr(args,'expected_reconcile_request_sha256',None)is not None or getattr(args,'withhold_unowned_target_ref',[]))and getattr(args,'command',None)!='account-copy-reconcile':raise MirrorError('unsupported_mirror_option')
        config = load_source_config(args.source_config, physical=args.read_mode != 'local')
        if getattr(args, 'voice_database', None):
            raise MirrorError('explicit_source_conflict')
        runtime_root = getattr(args, 'voice_runtime_root', None)
        runtime_python = getattr(args, 'voice_python', None)
        if bool(runtime_root) != bool(runtime_python):
            raise MirrorError('voice_runtime_pair_required')
        if runtime_root is not None:
            if not args.voice_transcripts:
                raise MirrorError('voice_transcripts_required')
            config = dict(config, voice_runtime_root=str(runtime_root), voice_python=str(runtime_python))
        request = dict(username=args.conversation_username, query=args.contact_query or args.group_query, limit=args.latest or args.display_limit, voice_transcripts=args.voice_transcripts, images=args.configured_images, target_kind='group' if args.group_query else 'private' if args.contact_query else None)
        if args.request:
            from datetime import datetime, timezone
            from zoneinfo import ZoneInfo
            from .window_time import parse_time_window, _inclusive_source_seconds
            zone = args.timezone or config.get('query_timezone')
            if not zone:
                raise MirrorError('timezone_required')
            window = parse_time_window(args.request, now=datetime.now(timezone.utc), timezone=ZoneInfo(zone))
            request['start'], request['end'] = _inclusive_source_seconds(window)
        stage('query')
        result = query_mirror(config, request, read_mode=args.read_mode)
        print(json.dumps(result, ensure_ascii=False))
        return 1 if result['gaps'] else 0
    except (MirrorError, ValueError, OSError, sqlite3.Error) as error:
        print(json.dumps(dict(error='mirror_query_failed', **error_fields(error))))
        return 2


@boundary('sync')
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['registry-reuse','init','once','media','image-redecode','status','schedule-status','query','enable','disable','bounded',
        'follow-enable','follow-disable','follow-status','follow-run','follow-recover-terminal',
        'follow-legacy-retirement-plan','follow-legacy-retire-after-boot','follow-current-state-recovery-plan','follow-current-state-recover',
        'alias-propose','alias-confirm','alias-list','alias-remove','request','request-status','directory-probe','directory-probe-status','recovery-plan','recover-source','recovery-status','scope-add-plan','scope-add-apply','scope-add-status','scope-add-recover','account-scope-status','account-scope-plan','account-scope-apply','account-scope-recover','account-scope-reanchor','account-scope-migration-status','account-copy-reconcile','account-shard-restore-plan','account-shard-restore','account-shard-restore-status'])
    parser.add_argument('--source-config', required=True, type=Path)
    parser.add_argument('--image-job-key')
    parser.add_argument('--legacy-retirement-id')
    parser.add_argument('--legacy-retirement-plan-sha256')
    parser.add_argument('--authorize-legacy-retirement',action='store_true')
    parser.add_argument('--authorize-current-state-recovery',action='store_true')
    parser.add_argument('--current-recovery-owner-sha256')
    parser.add_argument('--current-recovery-preboot-receipt',type=Path)
    parser.add_argument('--current-recovery-preboot-receipt-sha256')
    parser.add_argument('--current-recovery-witness-id')
    parser.add_argument('--current-recovery-witness-fingerprint')
    parser.add_argument('--scope-plan',type=Path)
    parser.add_argument('--account-plan',type=Path)
    parser.add_argument('--account-plan-sha256')
    parser.add_argument('--registered-target-ref')
    parser.add_argument('--restore-plan',type=Path)
    parser.add_argument('--restore-plan-sha256')
    parser.add_argument('--replacement-file',type=Path)
    parser.add_argument('--scope-plan-sha256')
    parser.add_argument('--scope-probe-record',type=Path)
    parser.add_argument('--scope-probe-record-sha256')
    parser.add_argument('--scope-recovery-diagnostic',type=Path)
    parser.add_argument('--scope-recovery-diagnostic-sha256')
    parser.add_argument('--operation-record', type=Path)
    parser.add_argument('--operation-token')
    parser.add_argument('--policy-record', type=Path)
    parser.add_argument('--policy-sha256')
    parser.add_argument('--follow-grant', type=Path)
    parser.add_argument('--follow-grant-sha256')
    parser.add_argument('--round-deadline')
    parser.add_argument('--early-preview',action='store_true')
    parser.add_argument('--media-segment-token',help=argparse.SUPPRESS)
    parser.add_argument('--duration-seconds', type=int)
    parser.add_argument('--username')
    parser.add_argument('--contact-query')
    parser.add_argument('--target-ref',type=Path)
    parser.add_argument('--target-ref-sha256')
    parser.add_argument('--latest',type=int)
    parser.add_argument('--since',type=int)
    parser.add_argument('--until',type=int)
    parser.add_argument('--timezone')
    parser.add_argument('--authorize-copy',action='store_true')
    parser.add_argument('--authorize-current-reconcile',action='store_true')
    parser.add_argument('--expected-reconcile-request-sha256')
    parser.add_argument('--withhold-unowned-target-ref',action='append',default=[])
    parser.add_argument('--request-record',type=Path)
    parser.add_argument('--terminal-revoked-origin',type=Path)
    parser.add_argument('--terminal-revoked-origin-sha256')
    parser.add_argument('--authorize-terminal-recovery',action='store_true')
    parser.add_argument('--expected-policy-generation')
    parser.add_argument('--expected-source-sha256')
    parser.add_argument('--authorize-directory-probe',action='store_true')
    parser.add_argument('--probe-record',type=Path)
    parser.add_argument('--expected-local-sha256')
    parser.add_argument('--authorize-source-verification',action='store_true')
    parser.add_argument('--accept-verified-identity',action='store_true')
    parser.add_argument('--refresh-authorized-auxiliary',action='store_true')
    parser.add_argument('--recovery-record',type=Path)
    parser.add_argument('--alias')
    parser.add_argument('--target-kind', choices=['private','group'], default='private')
    parser.add_argument('--proposal-id')
    parser.add_argument('--confirmed', action='store_true')
    parser.add_argument('--replace', action='store_true')
    parser.add_argument('--expected-username')
    parser.add_argument('--expected-revision', type=int)
    parser.add_argument('--read-mode', choices=['local','refresh'], default='local')
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--start', type=int)
    parser.add_argument('--end', type=int)
    args = parser.parse_args(argv)
    try:
        if args.command=='bounded' and args.operation_record is not None and args.operation_token is not None:
            from .native_background import bootstrap
            bootstrap(args.operation_record,args.operation_token,argv=None if argv is None else [sys.argv[0]]+list(argv))
        stage('configuration')
        if (getattr(args,'authorize_current_reconcile',False)or getattr(args,'expected_reconcile_request_sha256',None)is not None or getattr(args,'withhold_unowned_target_ref',[]))and getattr(args,'command',None)!='account-copy-reconcile':raise MirrorError('unsupported_mirror_option')
        if (args.authorize_terminal_recovery or args.terminal_revoked_origin is not None or args.terminal_revoked_origin_sha256 is not None) and args.command!='follow-recover-terminal':
            raise MirrorError('unsupported_mirror_option')
        if args.expected_policy_generation is not None and args.command not in ('follow-recover-terminal','follow-legacy-retirement-plan'):
            raise MirrorError('unsupported_mirror_option')
        if args.authorize_legacy_retirement and args.command not in ('follow-legacy-retirement-plan','follow-legacy-retire-after-boot'):
            raise MirrorError('unsupported_mirror_option')
        if (args.legacy_retirement_id is not None or args.legacy_retirement_plan_sha256 is not None) and args.command not in ('follow-legacy-retirement-plan','follow-legacy-retire-after-boot','follow-current-state-recovery-plan'):
            raise MirrorError('unsupported_mirror_option')
        current_commands=('follow-current-state-recovery-plan','follow-current-state-recover')
        if (args.authorize_current_state_recovery or any(x is not None for x in (args.current_recovery_owner_sha256,args.current_recovery_preboot_receipt,args.current_recovery_preboot_receipt_sha256,args.current_recovery_witness_id,args.current_recovery_witness_fingerprint))) and args.command not in current_commands:
            raise MirrorError('unsupported_mirror_option')
        if args.command=='follow-current-state-recovery-plan' and (args.current_recovery_witness_id is not None or args.current_recovery_witness_fingerprint is not None):
            raise MirrorError('unsupported_mirror_option')
        if args.command=='follow-current-state-recover' and any(x is not None for x in (args.expected_source_sha256,args.current_recovery_owner_sha256,args.current_recovery_preboot_receipt,args.current_recovery_preboot_receipt_sha256)):
            raise MirrorError('unsupported_mirror_option')
        if (args.scope_recovery_diagnostic is not None or args.scope_recovery_diagnostic_sha256 is not None) and args.command!='scope-add-plan':
            raise MirrorError('unsupported_mirror_option')
        if (args.scope_recovery_diagnostic is None)!=(args.scope_recovery_diagnostic_sha256 is None):
            raise MirrorError('scope_add_recovery_diagnostic_required')
        if (args.scope_probe_record is not None or args.scope_probe_record_sha256 is not None) and args.command!='scope-add-plan':
            raise MirrorError('unsupported_mirror_option')
        if (args.scope_probe_record is None)!=(args.scope_probe_record_sha256 is None):
            raise MirrorError('scope_add_probe_pin_required')
        if (args.scope_plan is not None or args.scope_plan_sha256 is not None) and not args.command.startswith('scope-add-'):
            raise MirrorError('unsupported_mirror_option')
        if args.operation_token is not None and args.command != 'follow-run' and (args.operation_record is None or args.command not in ('once','media','bounded')):
            raise MirrorError('unsupported_mirror_option')
        if (args.policy_record is not None or args.policy_sha256 is not None) and args.command != 'follow-run':
            raise MirrorError('unsupported_mirror_option')
        if (args.follow_grant is not None or args.follow_grant_sha256 is not None) and (args.command != 'bounded' or args.operation_record is None):
            raise MirrorError('unsupported_mirror_option')
        if args.early_preview and (args.command!='media' or args.operation_record is None or args.round_deadline is None):
            raise MirrorError('unsupported_mirror_option')
        if args.media_segment_token is not None and (args.command!='media' or args.operation_record is None
                or args.round_deadline is None or args.early_preview):
            raise MirrorError('unsupported_mirror_option')
        if args.round_deadline is not None and (args.command not in ('once','media') or args.operation_record is None):
            raise MirrorError('unsupported_mirror_option')
        if args.operation_record is not None and args.command not in ('once', 'media', 'bounded'):
            raise MirrorError('unsupported_mirror_option')
        if args.duration_seconds is not None and args.command != 'enable':
            raise MirrorError('unsupported_mirror_option')
        if args.command == 'image-redecode':
            if (args.image_job_key is None or args.read_mode != 'local'
                    or args.username is not None or args.target_ref is not None):
                raise MirrorError('image_redecode_job_reference')
            from .native_scope_add import scope_guard
            image_profile = scope_guard(args.source_config)
        elif args.image_job_key is not None:
            raise MirrorError('unsupported_mirror_option')
        offline_config = args.command.startswith(('follow-','account-scope-')) or args.command in ('registry-reuse','account-copy-reconcile','image-redecode','enable','disable','bounded','schedule-status','request','request-status','directory-probe','directory-probe-status','recovery-plan','recover-source','recovery-status') or args.operation_record is not None or (args.command in ('query','status') and args.read_mode == 'local')
        config = {} if args.command in ('follow-disable','follow-status','scope-add-plan','scope-add-apply','scope-add-status','scope-add-recover','account-scope-plan','account-scope-apply','account-scope-recover','account-scope-migration-status','account-shard-restore-plan','account-shard-restore','account-shard-restore-status') else load_source_config(args.source_config, physical=not offline_config)
        scope = config.get('mirror_scope', [])
        if args.command.startswith('account-shard-restore'):
            from . import native_shard_restore as restore
            if args.restore_plan is None:raise MirrorError('shard_restore_plan_required')
            if args.command=='account-shard-restore-plan':
                if args.replacement_file is None or args.registered_target_ref is None:raise MirrorError('shard_restore_input_required')
                result=restore.plan(args.source_config,args.replacement_file,args.registered_target_ref,args.restore_plan)
            else:
                if args.restore_plan_sha256 is None:raise MirrorError('shard_restore_plan_pin_required')
                # The plan pins its exact profile; argv cannot name a different one.
                p,_=restore._load(args.restore_plan,args.restore_plan_sha256)
                if str(args.source_config.absolute())!=p['profile']:raise MirrorError('shard_restore_profile_changed')
                result=restore.status(args.restore_plan,args.restore_plan_sha256) if args.command.endswith('-status') else restore.restore(args.restore_plan,args.restore_plan_sha256,confirmed=args.confirmed)
        elif args.command=='registry-reuse':
            from .native_registry_migrate import migrate
            result=migrate(config,args.source_config,confirmed=args.confirmed,expected_source_sha256=args.expected_source_sha256)
        elif args.command=='account-copy-reconcile':
            from .native_account_reconcile import authorize
            result=authorize(config,args.registered_target_ref,confirmed=args.confirmed,expected_source_sha256=args.expected_source_sha256,current=args.authorize_current_reconcile,expected_request_sha256=args.expected_reconcile_request_sha256,profile_path=args.source_config,withheld_refs=args.withhold_unowned_target_ref)
        elif args.command.startswith('account-scope-'):
            from .native_scope_contract import account_status, reanchor_cli
            if args.command=='account-scope-status':result=account_status(config,offset=args.offset,limit=args.limit,include_targets=True)
            elif args.command=='account-scope-reanchor':
                result=reanchor_cli(config,args.source_config,expected_source_sha256=args.expected_source_sha256,
                                    authorize=args.authorize_source_verification,accept=args.accept_verified_identity)
            else:
                from . import native_scope_migrate as migration
                if args.account_plan is None:raise MirrorError('account_migration_plan_required')
                if args.command=='account-scope-plan':result=migration.plan(args.source_config,args.account_plan)
                else:
                    pinned,_=migration._plan(args.account_plan,args.account_plan_sha256)
                    if pinned['profile']!=str(args.source_config.absolute()):raise MirrorError('account_migration_profile_conflict')
                    result=migration.status(args.account_plan,args.account_plan_sha256) if args.command=='account-scope-migration-status' else migration.apply(args.account_plan,args.account_plan_sha256)
        elif args.command.startswith('scope-add-'):
            from .source_setup import load_source_config as read_config
            from .native_scope_contract import mode
            if args.command=='scope-add-plan' and mode(read_config(args.source_config,physical=False))!='selected':raise MirrorError('scope_add_selected_only')
            from . import native_scope_add as scope_add
            if args.scope_plan is None:raise MirrorError('scope_add_plan_required')
            if args.command=='scope-add-plan':
                if args.target_ref is None or args.target_ref_sha256 is None:raise MirrorError('scope_add_reference_required')
                result=scope_add.plan(args.source_config,args.target_ref,args.target_ref_sha256,args.scope_plan,probe_record=args.scope_probe_record,probe_record_sha=args.scope_probe_record_sha256,recovery_diagnostic=args.scope_recovery_diagnostic,recovery_diagnostic_sha=args.scope_recovery_diagnostic_sha256)
            else:
                if str(args.source_config.absolute())!=scope_add._plan(args.scope_plan,args.scope_plan_sha256)['profile']:raise MirrorError('scope_add_profile_conflict')
                result=getattr(scope_add,{'scope-add-apply':'apply','scope-add-status':'status','scope-add-recover':'recover'}[args.command])(args.scope_plan,args.scope_plan_sha256)
        elif args.command.startswith('follow-'):
            from . import native_follow
            if args.command in ('follow-current-state-recovery-plan','follow-current-state-recover'):
                from . import native_follow_current_recovery as recovery
                if args.command=='follow-current-state-recovery-plan':
                    result=recovery.plan(args.source_config,expected_source_sha256=args.expected_source_sha256,
                        legacy_retirement_id=args.legacy_retirement_id,legacy_plan_sha256=args.legacy_retirement_plan_sha256,
                        legacy_owner_sha256=args.current_recovery_owner_sha256,preboot_receipt=args.current_recovery_preboot_receipt,
                        preboot_receipt_sha256=args.current_recovery_preboot_receipt_sha256,authorize=args.authorize_current_state_recovery)
                else:
                    result=recovery.apply(args.source_config,witness_id=args.current_recovery_witness_id,
                        witness_fingerprint=args.current_recovery_witness_fingerprint,authorize=args.authorize_current_state_recovery)
            elif args.command in ('follow-legacy-retirement-plan','follow-legacy-retire-after-boot'):
                from . import native_follow_legacy as legacy
                if args.command=='follow-legacy-retirement-plan':
                    result=legacy.plan(args.source_config,expected_source_sha256=args.expected_source_sha256,
                        expected_policy_generation=args.expected_policy_generation,authorize=args.authorize_legacy_retirement)
                else:
                    result=legacy.apply(args.source_config,retirement_id=args.legacy_retirement_id,
                        plan_sha256=args.legacy_retirement_plan_sha256,authorize=args.authorize_legacy_retirement)
            elif args.command == 'follow-recover-terminal':
                from .native_follow_terminal import recover
                result = recover(args.source_config,expected_source_sha256=args.expected_source_sha256,
                                 expected_policy_generation=args.expected_policy_generation,authorize=args.authorize_terminal_recovery,
                                 revoked_origin=args.terminal_revoked_origin,revoked_origin_sha256=args.terminal_revoked_origin_sha256)
            elif args.command == 'follow-enable':
                result = native_follow.enable(config,args.source_config,Path(sys.executable).parent/'wechat-local-sync')
            elif args.command == 'follow-disable':
                result = native_follow.disable(args.source_config)
            elif args.command == 'follow-status':
                result = native_follow.status(args.source_config)
            else:
                if args.policy_record is None or args.policy_sha256 is None or args.operation_token is None:
                    raise MirrorError('follow_policy_unknown')
                result = native_follow.run_listener(args.policy_record,args.policy_sha256,operation_token=args.operation_token)
        elif args.command.startswith('alias-'):
            from .confirmed_aliases import propose_alias, confirm_alias, list_aliases, remove_alias
            if args.command == 'alias-propose':
                result = propose_alias(config, args.alias, args.username, args.target_kind)
            elif args.command == 'alias-confirm':
                result = confirm_alias(config, args.alias, args.username, args.proposal_id,
                    confirmed=args.confirmed, replace=args.replace, expected_username=args.expected_username)
            elif args.command == 'alias-remove':
                result = remove_alias(config, args.alias, expected_revision=args.expected_revision, confirmed=args.confirmed)
            else:
                result = list_aliases(config)
        elif args.command in ('recovery-plan','recover-source','recovery-status'):
            from .native_recovery_role import local_plan,prepare as recovery_prepare,status as recovery_status,CODES
            try:
                if args.command=='recovery-plan':result=local_plan(config)
                elif args.command=='recovery-status':
                    if args.recovery_record is None:raise MirrorError('recovery_record_required')
                    result=recovery_status(args.recovery_record,config=config,config_path=args.source_config)
                else:result=recovery_prepare(config,args.source_config,expected_source_sha256=args.expected_source_sha256,expected_local_sha256=args.expected_local_sha256,authorize=args.authorize_source_verification,accept=args.accept_verified_identity,refresh_auxiliary=args.refresh_authorized_auxiliary)
            except (MirrorError,ValueError,KeyError,TypeError,OSError,sqlite3.Error) as error:
                code=str(error)
                result=dict(status='failed',stage='source_recovery',reason=code if code in CODES or code=='recovery_record_required' else 'recovery_guard_or_device_failed',source_opened=None if args.command=='recover-source' and args.authorize_source_verification else False,local_mutated=None if args.command=='recover-source' and args.authorize_source_verification and args.accept_verified_identity else False)
        elif args.command in ('directory-probe','directory-probe-status'):
            try:
                from .native_directory_probe import prepare as probe_prepare,status as probe_status
                if args.command=='directory-probe-status':
                    if args.probe_record is None:raise MirrorError('probe_record_required')
                    result=probe_status(args.probe_record,config=config,config_path=args.source_config)
                else:
                    result=probe_prepare(config,args.source_config,expected_sha256=args.expected_source_sha256,authorize=args.authorize_directory_probe)
            except (MirrorError,ValueError,KeyError,TypeError,OSError):
                result=dict(status='failed',stage='directory_discovery',reason='directory_probe_unavailable',source_sql_access='not_tested')
        elif args.command in ('request','request-status'):
            try:
                from .native_target_request import prepare,status,window_spec
                if args.command=='request-status':
                    if args.request_record is None:raise MirrorError('request_record_required')
                    result=status(args.request_record,config=config,config_path=args.source_config)
                else:
                    if bool(args.contact_query)==bool(args.target_ref):raise MirrorError('request_target_required')
                    result=prepare(config,args.source_config,query=args.contact_query,reference=args.target_ref,reference_sha=args.target_ref_sha256,window=window_spec(args.latest,args.since,args.until,args.timezone),authorize=args.authorize_copy)
            except (MirrorError,ValueError,KeyError,TypeError,OSError) as error:
                codes={'request_target_unconfirmed','request_source_conflict','request_metadata_stale','request_window_invalid','request_window_crosses_date','request_snapshot_conflict','request_cache_conflict','request_reference_conflict','request_app_unavailable','request_context_changed','request_authorization_required','request_location_invalid','request_target_required','request_record_required','request_reference_invalid'}
                reason=str(error)
                result=dict(status='failed',reason=reason if reason in codes else 'request_unavailable',source_opened=None if args.authorize_copy else False)
        elif args.command == 'image-redecode':
            from .native_deadline import Deadline, activate_deadline
            from .image_runtime import ImageUnavailable
            from .native_image_redecode import redecode
            stage('local_image_decode')
            with activate_deadline(Deadline.create(30)):
                try:
                    result = redecode(config,args.image_job_key,
                                      validate_profile=lambda: scope_guard(args.source_config,image_profile))
                except (TypeError,KeyError,ImageUnavailable) as error:
                    raise MirrorError('image_redecode_binding') from error
        elif args.command == 'media':
            if args.operation_record is None or args.operation_token is None:
                raise MirrorError('owned_media_operation_required')
            from .native_media_work import run_media
            from .live_readonly import read_private_passphrase,open_encrypted_readonly
            secret=[None]
            def opener(path):
                if secret[0] is None:secret[0]=read_private_passphrase(Path(config['passphrase_file']))
                return open_encrypted_readonly(path,secret[0])[0]
            runtime=None
            if config.get('voice_runtime_root') and config.get('voice_python'):
                from .local_voice_runtime import LocalWhisperTranscriber
                runtime=LocalWhisperTranscriber(Path(config['voice_runtime_root']),Path(config['voice_python']))
            def media_action(*,media_sources=None,media_validate=None):
                from .local_image_runtime import LocalVisionRecognizer
                from .native_media_dispatch import run
                vision=LocalVisionRecognizer(mirror_root(config,create=False)/'image-ocr-runtime')
                return dict(gaps=[],**run(config,opener,transcriber=runtime,
                    decoder=runtime.decode_audio if runtime is not None else None,recognizer=vision,**(dict(media_sources=media_sources,media_validate=media_validate) if media_sources is not None else {})))
            def preview_action(ref,*,validate):
                from .native_image_preview import run
                return run(config,ref,opener,validate=validate)
            try:
                result=run_owned_once(config,args.source_config,args.operation_record,media_action,
                    operation_token=args.operation_token,round_deadline=json.loads(args.round_deadline) if args.round_deadline else None,
                    follow_action=media_action,owned_media=True,
                    early_preview=preview_action if args.early_preview else None,
                    media_segment_token=args.media_segment_token,
                    request_media_devices=dict(transcriber=runtime,decoder=runtime.decode_audio if runtime is not None else None))
            finally:secret[0]=None
        elif args.command in ('init','once'):
            stage('synchronize')
            def owned_action():
                from .native_schedule import _read
                record=json.loads(_read(args.operation_record)[0])
                if record.get('follow_grant'):
                    from .native_follow_grant import load
                    if load(record['follow_grant'],record['follow_grant_sha256']).get('kind')=='request':
                        from .native_target_request import copy_window
                        return copy_window(config,args.operation_record)
                return sync_once(config,scope,capture_media=False)
            if args.operation_record is not None:
                result = run_owned_once(config, args.source_config, args.operation_record, lambda: sync_once(config, scope),
                    operation_token=args.operation_token,
                    round_deadline=json.loads(args.round_deadline) if args.round_deadline is not None else None,
                    follow_action=owned_action)
            else:
                result = sync_once(config, scope, initialize=args.command == 'init')
        elif args.command == 'bounded':
            stage('schedule')
            if args.operation_record is None:
                raise MirrorError('schedule_state_unknown')
            result = run_bounded(config, args.source_config, args.operation_record, operation_token=args.operation_token)
        elif args.command == 'query':
            request = dict(username=args.username, limit=args.limit, offset=args.offset)
            if args.registered_target_ref is not None:request['target_ref']=args.registered_target_ref
            request.update({name: getattr(args, name) for name in ('start','end') if getattr(args,name) is not None})
            stage('query')
            result = query_mirror(config, request, read_mode=args.read_mode)
        elif args.command == 'schedule-status':
            result = schedule_status(config, args.source_config, Path(sys.executable).parent / 'wechat-local-sync', Path.home() / 'Library/LaunchAgents')
        elif args.command == 'status':
            # No usernames, bodies, credentials, or source filesystem probes.
            result = mirror_status(config)
        else:
            stage('schedule')
            executable = Path(sys.executable).parent / 'wechat-local-sync'
            path = configure_schedule(config, args.source_config, executable, Path.home() / 'Library/LaunchAgents', args.command == 'enable', duration_seconds=args.duration_seconds if args.duration_seconds is not None else 600)
            result = dict(enabled=args.command == 'enable')
            if args.command == 'enable':
                result.update(sync_health='waiting_first_sync', first_sync_completed=False,
                              health_evidence='not_observed', next_step='schedule-status')
            else:
                result['next_step'] = 'schedule-status'
        from .failure_evidence import phase
        if args.operation_record is not None and args.command in ('once','media') and result.get('gaps'):
            partial = partial_source(result) if args.command == 'once' else None
            result.update(failure_details([*result['gaps'], result.get('failure_reason')]))
            if partial is not None:
                result['failure_class'] = 'partial_retryable'
        if args.command in ('once','media','bounded'):phase('output_started')
        displayed = result
        if (args.command == 'once' and args.operation_record is not None
                and os.environ.get('WALDEN_FOLLOW_CONTROL_RESULT') == '1'):
            displayed = control_result(result)
        print(json.dumps(displayed, ensure_ascii=False))
        if args.command in ('once','media','bounded'):phase('output_returned')
        from .native_background import CleanupPending
        if args.command=='bounded' and isinstance(result,CleanupPending):
            from .failure_evidence import mark_cleanup_pending
            mark_cleanup_pending(result);return 75
        if args.command=='media':
            from .native_media_segment import YieldResult, YIELD_EXIT
            if isinstance(result,YieldResult):return YIELD_EXIT
        return 1 if result.get('gaps') else 0
    except AliasError as error:
        print(json.dumps(dict(status='uncertain' if error.reason == 'alias_commit_uncertain' else 'unavailable', error=error.reason, **error_fields(error))))
        return 2
    except (MirrorError, ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError) as error:
        detail = {}
        if args.command == 'image-redecode':
            reasons = {'image_redecode_job_reference','image_redecode_job_unavailable','image_redecode_job_binding',
                       'image_redecode_saved_binding','image_redecode_file_binding','image_redecode_saved_digest',
                       'image_redecode_file_changed','image_redecode_job_changed','image_redecode_failed',
                       'image_decoder_config_invalid','image_decoder_settings_invalid','image_redecode_binding','sync_busy',
                       'cursor_generation_media_unavailable','scope_copy_proof','media_message_changed',
                       'account_scope_receipt_invalid','schedule_deadline_expired'}
            reason = str(error)
            detail = dict(reason=reason if reason in reasons else 'image_redecode_unavailable',source_opens=0)
        if args.operation_record is not None and args.command in ('once','media'):
            reason = 'invalid_source_configuration' if isinstance(error, SourceSetupError) else str(error)
            detail = failure_details([reason])
        print(json.dumps(dict(error='mirror_operation_failed', **error_fields(error), **detail)))
        return 2


def console_main(argv=None):
    return console(main, argv)


_register(query_mirror, configure_schedule, mirror_status, window_main, main, console_main,
          exception_types={MirrorError: 'MirrorError', AliasError: 'AliasError', SourceSetupError: 'SourceSetupError'})


if __name__ == '__main__':
    raise SystemExit(console_main())
