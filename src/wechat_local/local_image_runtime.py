"""Local Apple Vision OCR; accepts only bounded, caller-verified PNG bytes."""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess

MAX_PNG = 32 * 1024 * 1024
LANGUAGES = ('zh-Hans', 'en-US')
SWIFT = r'''import Foundation
import Vision
let data = FileHandle.standardInput.readDataToEndOfFile()
let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.recognitionLanguages = ["zh-Hans", "en-US"]
request.usesLanguageCorrection = false
try VNImageRequestHandler(data: data).perform([request])
let rows = (request.results ?? []).compactMap { item -> [String: Any]? in
    guard let best = item.topCandidates(1).first else { return nil }
    let b = item.boundingBox
    return ["text": best.string, "confidence": best.confidence,
            "bounds": [b.origin.x, b.origin.y, b.width, b.height]]
}
let result: [String: Any] = ["rows": rows, "revision": request.revision,
    "languages": request.recognitionLanguages,
    "system": ProcessInfo.processInfo.operatingSystemVersionString]
let output = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
FileHandle.standardOutput.write(output)
'''


class LocalImageRuntimeError(RuntimeError):
    pass


class LocalVisionRecognizer:
    """Compile the fixed helper in a private mirror directory; no network or model downloads."""
    def __init__(self, runtime_root):
        self.root = Path(runtime_root)
        self.identity = 'apple-vision:' + platform.mac_ver()[0] + ':' + platform.version() + ':' + hashlib.sha256(SWIFT.encode()).hexdigest()
        self.languages = LANGUAGES

    def _prepare(self):
        import fcntl
        self.root.mkdir(mode=0o700, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise LocalImageRuntimeError('ocr_runtime_binding')
        fd = os.open(self.root / '.build.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise LocalImageRuntimeError('ocr_runtime_binding')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LocalImageRuntimeError('ocr_build_busy') from None
            return self._build()
        finally:
            os.close(fd)

    def _build(self):
        if platform.system() != 'Darwin':
            raise LocalImageRuntimeError('ocr_runtime_unavailable')
        self.root.mkdir(mode=0o700, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise LocalImageRuntimeError('ocr_runtime_binding')
        tag = hashlib.sha256(self.identity.encode()).hexdigest()
        binary = self.root / ('vision-' + tag)
        if binary.exists():
            info = binary.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o700:
                raise LocalImageRuntimeError('ocr_runtime_binding')
            return binary
        source = self.root / ('vision-' + tag + '.swift')
        # An exclusive file prevents following pre-existing links or replacing foreign content.
        try:
            fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600 or stream.read(len(SWIFT.encode()) + 1) != SWIFT.encode()):
                    raise LocalImageRuntimeError('ocr_runtime_binding')
        else:
            with os.fdopen(fd, 'w') as stream:
                stream.write(SWIFT)
        cache = self.root / 'module-cache'
        cache.mkdir(mode=0o700, exist_ok=True)
        if cache.is_symlink() or not cache.is_dir():
            raise LocalImageRuntimeError('ocr_runtime_binding')
        import secrets
        temporary = self.root / ('vision-' + tag + '.' + secrets.token_hex(8) + '.building')
        if temporary.exists() or temporary.is_symlink():
            raise LocalImageRuntimeError('ocr_build_incomplete')
        try:
            subprocess.run(['/usr/bin/xcrun', 'swiftc', '-module-cache-path', str(cache), str(source), '-o', str(temporary)],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, check=True, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
            os.chmod(temporary, 0o700)
            os.replace(temporary, binary)
        except (OSError, subprocess.SubprocessError):
            raise LocalImageRuntimeError('ocr_build_unavailable') from None
        return binary

    def recognize_png(self, payload, timeout=30):
        if not payload.startswith(b'\x89PNG\r\n\x1a\n') or len(payload) > MAX_PNG:
            raise LocalImageRuntimeError('ocr_input_invalid')
        binary = self._prepare()
        try:
            result = subprocess.run([str(binary)], input=payload, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, check=True, timeout=timeout,
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
            if len(result.stdout) > 1024 * 1024:
                raise ValueError
            value = json.loads(result.stdout)
            rows = value['rows']
            if type(rows) is not list or any(type(r.get('text')) is not str for r in rows):
                raise ValueError
            return dict(text='\n'.join(r['text'] for r in rows), regions=rows,
                        engine='apple_vision', engine_identity=self.identity,
                        system=value['system'], revision=value['revision'], languages=value['languages'])
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            raise LocalImageRuntimeError('ocr_recognition_failed') from None
