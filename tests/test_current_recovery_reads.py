"""Private legal fixtures: protected bodies must never be opened as recovery input."""
import os
from pathlib import Path
import pytest
from wechat_local import native_follow_current_recovery as recovery
from wechat_local.native_mirror_store import MirrorError
from test_current_recovery import incident,prepare,recover
from test_follow_legacy import item


def watch(monkeypatch,protected):
    objects={(p.stat().st_dev,p.stat().st_ino)for p in protected};reads=[];original=os.read
    def read(fd,size):
        s=os.fstat(fd)
        if (s.st_dev,s.st_ino)in objects:reads.append(size)
        return original(fd,size)
    monkeypatch.setattr(os,'read',read)
    return reads


@pytest.mark.parametrize('role',['receipt','plan','owner','control'])
@pytest.mark.parametrize('target_role',['source','credential'])
def test_each_basis_or_control_role_rejects_protected_body(incident,monkeypatch,role,target_role):
    t=incident
    target=Path(t.config['message_root'])/'message_0.db' if target_role=='source' else Path(t.config['passphrase_file'])
    if not target.exists():target.write_bytes(b's'*32)
    target.chmod(0o600);reads=watch(monkeypatch,[target])
    if role=='receipt':t.inputs['preboot_receipt']=target
    else:
        name={'plan':'legacy-plan.'+t.generation+'.json','owner':'legacy-owner.'+t.generation+'.json','control':'source.'+t.generation+'.json'}[role]
        link=t.store.path(name);link.rename(link.with_suffix('.kept'));link.symlink_to(target)
    with pytest.raises((MirrorError,OSError)):prepare(t)
    assert reads==[] and not t.store.path(recovery._name('ticket',t.generation)).exists()


@pytest.mark.parametrize('kind',['parent_source','parent_credential','hardlink_credential','source_hardlink'])
def test_aliases_rejected_before_body(incident,monkeypatch,kind):
    t=incident;credential=Path(t.config['passphrase_file']);credential.write_bytes(b's'*32);credential.chmod(0o600)
    source=Path(t.config['message_root'])/'message_0.db';source.chmod(0o600)
    reads=watch(monkeypatch,[credential,source]);alias=t.profile.parent/'input-alias'
    if kind.startswith('parent_'):
        target=source if kind=='parent_source' else credential
        alias.symlink_to(target.parent,target_is_directory=True);t.inputs['preboot_receipt']=alias/target.name
    else:
        os.link(credential if kind=='hardlink_credential' else source,alias);t.inputs['preboot_receipt']=alias
    with pytest.raises((MirrorError,OSError)):prepare(t)
    assert reads==[]


@pytest.mark.parametrize('kind',['source','source_parent_alias','credential_hardlink'])
def test_output_root_rejected_before_create(incident,monkeypatch,kind):
    t=incident;source=Path(t.config['message_root']);target=source/'new-recovery-store'
    if kind=='source_parent_alias':
        alias=t.profile.parent/'source-alias';alias.symlink_to(source,target_is_directory=True);target=alias/'new-recovery-store'
    elif kind=='credential_hardlink':
        credential=Path(t.config['passphrase_file']);credential.write_bytes(b's'*32);credential.chmod(0o600)
        target=t.profile.parent/'hardlink-output';os.link(credential,target)
    t.inputs['root']=target;before=set(source.iterdir())
    with pytest.raises((MirrorError,OSError)):prepare(t)
    assert set(source.iterdir())==before and not (source/'new-recovery-store').exists()


@pytest.mark.parametrize('phase',['apply','proof'])
def test_receipt_reread_rejects_alias_after_witness(incident,monkeypatch,phase):
    from wechat_local import native_follow as follow
    t=incident;p=prepare(t)
    if phase=='proof':recover(t,p)
    receipt=t.inputs['preboot_receipt'];receipt.rename(receipt.with_suffix('.kept'))
    target=Path(t.config['message_root'])/'message_0.db';target.chmod(0o600);receipt.symlink_to(target)
    reads=watch(monkeypatch,[target])
    with pytest.raises((MirrorError,OSError)):
        if phase=='apply':recover(t,p)
        else:recovery.current_proof(t.store,follow._runtime(t.store),profile_path=t.profile)
    assert reads==[]


def test_opened_object_swap_refuses_before_fd_body_read(incident,monkeypatch):
    t=incident;target=Path(t.config['passphrase_file']);target.write_bytes(b's'*32);target.chmod(0o600)
    receipt=t.inputs['preboot_receipt'];reads=watch(monkeypatch,[target]);original=os.open;swapped=[]
    def opened(path,flags,*args,**kwargs):
        if Path(path)==receipt and not swapped:
            receipt.rename(receipt.with_suffix('.kept'));os.link(target,receipt);swapped.append(True)
        return original(path,flags,*args,**kwargs)
    monkeypatch.setattr(os,'open',opened)
    with pytest.raises((MirrorError,OSError)):prepare(t)
    assert swapped and reads==[]
