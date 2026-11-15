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
        self.conflict = False
        self.last_wait = clock()
        try:
            self._refresh()
        except BaseException:
            self.close()
            raise

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
            b = self.backend
            flags = b.KQ_NOTE_WRITE | b.KQ_NOTE_DELETE | b.KQ_NOTE_RENAME | b.KQ_NOTE_ATTRIB | b.KQ_NOTE_EXTEND | b.KQ_NOTE_REVOKE
            for fd in fresh:
                event = b.kevent(fd, filter=b.KQ_FILTER_VNODE,
                                 flags=b.KQ_EV_ADD | b.KQ_EV_ENABLE | b.KQ_EV_CLEAR, fflags=flags)
                self.queue.control([event], 0, 0)
            validate()
            for fd in self.fds:
                os.close(fd)
            self.fds = fresh
            self.identity = root_identity
            # Ancestors are traversal anchors only, never watched outside root.
            for fd in opened:
                if fd not in fresh:
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
