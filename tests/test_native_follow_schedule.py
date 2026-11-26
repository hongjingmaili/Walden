from wechat_local.native_follow_schedule import plan
from wechat_local.native_follow_state import transition

NS = 10**9
EPOCH = {'pid': 10, 'start': [1, 2]}
GENERATION = 'a' * 32


def completion(operation, now, *, exit_code=2, failure_class='retryable'):
    return dict(operation=operation, attempt=1, exit_code=exit_code, failure_class=failure_class,
                completed_at_ns=now*NS, completed_at_continuous_ns=now*NS)


def test_follow_retry_is_at_least_five_minutes_and_grows_across_workers():
    first = plan(None, wall=10, continuous=10*NS, interval=30, completion=completion('first',10))
    assert first['backoff'] == 300
    assert not plan(first, wall=9999, continuous=309*NS, interval=30, dirty=True)['due']
    assert plan(first, wall=310, continuous=310*NS, interval=30)['due']
    second = plan(first, wall=311, continuous=311*NS, interval=30, completion=completion('second',311))
    assert second['backoff'] == 600
    assert second['next_due_continuous_ns'] == 911*NS
    previous = second
    for step, expected in enumerate((1200,2400,3600,3600), start=3):
        now = previous['next_due_continuous_ns']//NS
        previous = plan(previous, wall=now, continuous=now*NS, interval=30,
                        completion=completion(f'worker-{step}',now))
        assert previous['backoff'] == expected


def test_follow_permanent_failure_blocks_until_new_policy():
    blocked = plan(None, wall=10, continuous=10*NS, interval=30,
                   completion=completion('first',10,failure_class='permanent'))
    assert blocked['mode'] == 'blocked'
    for value in (False,True):
        assert not plan(blocked, wall=50_000, continuous=50_000*NS,
                        interval=30, dirty=True, draining=value)['due']
    assert plan(blocked, wall=50_000, continuous=50_000*NS, interval=30, restart=True)['due']


def test_stopped_worker_backoff_carries_to_next_grant_without_app_epoch_bypass():
    previous = dict(policy_generation=GENERATION,app_epoch=EPOCH)
    worker = dict(active=False,stop_confirmed=True,kind='active',app_epoch=EPOCH,
                  policy_generation=GENERATION,operation='first',last_completed=completion('first',10))
    result = transition(previous,enabled=True,policy_generation=GENERATION,
                        app=dict(state='running',epoch=EPOCH),worker=worker,
                        wall=10,continuous=10*NS)
    assert result['state']=='waiting_source'
    assert result['source_schedule']['backoff']==300
    new_epoch = {'pid': 20, 'start': [3,4]}
    no_worker = dict(active=False, stop_confirmed=True)
    result = transition(result,enabled=True,policy_generation=GENERATION,
                        app=dict(state='running',epoch=new_epoch),worker=no_worker,
                        wall=9999,continuous=309*NS)
    assert result['action']=='wait'
    result = transition(result,enabled=True,policy_generation=GENERATION,
                        app=dict(state='running',epoch=new_epoch),worker=no_worker,
                        wall=9999,continuous=310*NS)
    assert result['action']=='start_active'
    assert result['source_schedule']['backoff']==300
