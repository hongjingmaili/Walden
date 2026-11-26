"""macOS vnode hints. No Source connection; transaction checks remain authoritative.

Directory descriptors discover new numeric shards and newly created WALs. A
bounded rescan happens only on a vnode hint, never on the lifecycle timer.
"""
import os
from pathlib import Path
import select
import stat
from .native_mirror_store import MirrorError
from .native_deadline import continuous_ns
from .source_catalog import SHARD_NAME_PATTERN


def _continuous_seconds():
    return continuous_ns()/1_000_000_000


class VnodeHints:
    def __init__(self, root, *, backend=select, clock=_continuous_seconds):
        if not hasattr(backend, 'kqueue'):
            raise MirrorError('follow_native_events_unsupported')
        self.root = Path(root)
        self.backend = backend
        self.clock = clock
        try:
            self.queue = backend.kqueue()
        except OSError:
            raise MirrorError('follow_native_events_failed') from None
        self.fds = {}
        self.identity = None
        self.generation = 1  # Startup/restart always reconciles once.
        self.shard_generations = {}
        self.fallback_generation = 0
        self.uncertain_generation = 1
        self.conflict = False
        self.last_wait = clock()
        try:
            self._refresh()
        except BaseException:
            self.close()
            raise

    def _data_shard(self,path):
        if path.parent!=self.root:return None
        name=path.name
        if name.endswith('.db-wal'):name=name[:-4]
        elif not name.endswith('.db'):return None
        return name if SHARD_NAME_PATTERN.fullmatch(name) else None

    def _publish(self,changed,unknown=False,*,uncertain=None):
        uncertain=unknown if uncertain is None else uncertain
        if len(set(self.shard_generations)|changed)>64:
            self.shard_generations.clear();unknown=True;uncertain=True
        else:self.shard_generations.update({name:self.generation for name in changed})
        if unknown:self.fallback_generation=self.generation
        if uncertain:self.uncertain_generation=self.generation

    def _refresh(self):
        # Every lookup/open is relative to an already opened directory FD.
        # Path objects below are labels only: no lookup follows an intermediate
        # pathname that another process can replace with an outside symlink.
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        file_flags = getattr(os, 'O_EVTONLY', os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
        opened = []
        links = []
        fresh = {}
        old_paths = {path for path, _ in self.fds.values()}
        old_entries={(path,stamp):fd for fd,(path,stamp) in self.fds.items()}
        initialized=self.identity is not None
        def identity(info):
            return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
        def open_child(parent, name, flags, label):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fd = os.open(name, flags, dir_fd=parent)
            opened.append(fd)
            if identity(os.fstat(fd)) != identity(before):
                raise MirrorError('follow_event_path_changed')
            links.append((parent, name, fd, identity(before)))
            return fd
        def validate():
            # Validate the entire named parent chain against the anchored FDs,
            # including directories renamed during child enumeration/opens.
            for parent, name, fd, expected in links:
                if (identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected
                        or identity(os.fstat(fd)) != expected):
                    raise MirrorError('follow_event_path_changed')
        try:
            if not self.root.is_absolute() or '..' in self.root.parts:
                raise MirrorError('follow_event_root_conflict')
            parent = os.open('/', directory_flags)
            opened.append(parent)
            for part in self.root.parts[1:]:
                parent = open_child(parent, part, directory_flags, self.root)
            root_fd = parent
            info = os.fstat(root_fd)
            root_identity = [info.st_dev, info.st_ino]
            if self.identity is not None and root_identity != self.identity:
                raise MirrorError('follow_event_root_conflict')
            def visit(fd, label):
                info = os.fstat(fd)
                fresh[fd] = (label, (info.st_dev, info.st_ino))
                for name in os.listdir(fd):
                    child_label = label/name
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        if child_label in old_paths:
                            raise MirrorError('follow_event_path_changed')
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        child = open_child(fd, name, directory_flags, child_label)
                        visit(child, child_label)
                    elif stat.S_ISREG(info.st_mode) and name.endswith(('.db', '.db-wal', '.db-shm')):
                        child = open_child(fd, name, file_flags, child_label)
                        current = os.fstat(child)
                        fresh[child] = (child_label, (current.st_dev, current.st_ino))
            visit(root_fd, self.root)
            validate()
            # Keep unchanged subscriptions alive. Closing and re-registering
            # them could lose a DB/WAL event queued during this refresh.
            reuse={}
            discovered=set()
            for fd,(path,stamp) in fresh.items():
                old=old_entries.get((path,stamp))
                if old is not None:
                    if identity(os.fstat(old))!=identity(os.fstat(fd)):
                        raise MirrorError('follow_event_path_changed')
                    reuse[fd]=old
                elif initialized:
                    name=self._data_shard(path)
                    if name is not None:discovered.add(name)
            b = self.backend
            flags = b.KQ_NOTE_WRITE | b.KQ_NOTE_DELETE | b.KQ_NOTE_RENAME | b.KQ_NOTE_ATTRIB | b.KQ_NOTE_EXTEND | b.KQ_NOTE_REVOKE
            for fd in fresh:
                if fd in reuse:continue
                event = b.kevent(fd, filter=b.KQ_FILTER_VNODE,
                                 flags=b.KQ_EV_ADD | b.KQ_EV_ENABLE | b.KQ_EV_CLEAR, fflags=flags)
                self.queue.control([event], 0, 0)
            validate()
            accepted={reuse.get(fd,fd):entry for fd,entry in fresh.items()}
            for fd in self.fds:
                if fd not in accepted:os.close(fd)
            self.fds = accepted
            self.identity = root_identity
            self._publish(discovered)
            # Ancestors are traversal anchors only, never watched outside root.
            for fd in opened:
                if fd not in self.fds:
                    os.close(fd)
            opened.clear()
        finally:
            # On any lookup/registration/validation failure, close every new
            # descriptor; the caller fails closed and retains dirty for restart.
            for fd in opened:
                os.close(fd)

    def wait(self, timeout):
        """Block for native events, with at most 100ms burst aggregation.

        Timeout is only the existing lifecycle observation budget. It never
        triggers a stat scan. A long wait (sleep/suspend) requests reconciliation.
        """
        try:
            events = self.queue.control(None, 256, max(0, timeout))
            now = self.clock()
            if now - self.last_wait > timeout + 5:
                self.generation += 1
                self.uncertain_generation=self.generation
            self.last_wait = now
            if events:
                self.generation += 1
                # A full buffer is a dirty hint. Explicit revocation means the
                # device no longer guarantees this watch: fail, revoke Source
                # admission and let a fresh listener rebind the original root.
                tail = self.queue.control(None, 256, .1)
                if any(getattr(event, 'fflags', 0) & self.backend.KQ_NOTE_REVOKE for event in events + tail):
                    raise MirrorError('follow_native_event_revoked')
                error_flag = getattr(self.backend, 'KQ_EV_ERROR', 0)
                if any(getattr(event, 'flags', 0) & error_flag for event in events + tail):
                    raise MirrorError('follow_native_event_delivery_error')
                # Resolve old descriptor identities before _refresh closes them.
                changed = set()
                coordination = set()
                unknown = len(events) == 256 or len(tail) == 256
                for event in events + tail:
                    entry = self.fds.get(getattr(event, 'ident', None))
                    if entry is None or entry[0].parent != self.root:
                        unknown = True
                        continue
                    name=self._data_shard(entry[0])
                    if name is not None:
                        changed.add(name)
                    elif entry[0].name.endswith('.db-shm') and SHARD_NAME_PATTERN.fullmatch(entry[0].name[:-4]):
                        coordination.add(entry[0].name[:-4])
                    else:unknown=True
                # SHM coordinates readers/writers; it is not message content.
                # Keep it dirty and discover conservatively without repeatedly
                # placing that shard ahead of all ordinary/history sources.
                self._publish(changed,unknown or bool(coordination-changed),uncertain=unknown)
                self._refresh()
            return self.generation
        except (OSError, MirrorError):
            self.conflict = True
            raise MirrorError('follow_native_events_failed') from None

    def close(self):
        for fd in self.fds:
            os.close(fd)
        self.fds.clear()
        self.queue.close()
