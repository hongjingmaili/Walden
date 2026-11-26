"""Private decoder preference for an unchanged account source configuration."""
import json

from .image_runtime import _explicit_decoder_path
from .native_mirror_store import MirrorError
from .native_scope_add import encoded, read
from .native_scope_contract import digest, mode

NAME = '.image-decoder-settings.json'
SCHEMA = 'walden.image-decoder-settings/1'


def record(config, path):
    return dict(schema=SCHEMA, source_config_sha256=digest(config),
                account_id=config['account_id'], source_generation=config['source_generation'],
                image_ffmpeg=str(path))


def decoder_path(config, root):
    """Resolve the explicit setting for media workers only; absence uses legacy defaults."""
    value = config.get('image_ffmpeg')
    try:
        # Preserve the priority of an already signed profile setting.
        if value is not None:
            return _explicit_decoder_path(value)
        if mode(config) != 'account':
            return None
        try:
            raw, _ = read(root/NAME,limit=8192)
        except FileNotFoundError:
            return None
        entry = json.loads(raw)
        path = _explicit_decoder_path(entry['image_ffmpeg'])
        if raw != encoded(record(config,path)):
            raise ValueError('decoder settings binding')
        return path
    except (ValueError, TypeError, KeyError, OSError, MirrorError) as error:
        raise MirrorError('image_decoder_settings_invalid') from error
