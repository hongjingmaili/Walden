"""Native local queries; only explicit refresh synchronizes authorized sources.

Optional reply compatibility requires pre-existing event evidence. Fresh native
init/refresh does not produce reply evidence; native refs cannot substitute.
"""
from __future__ import annotations
import argparse
from pathlib import Path
from .native_mirror_cli import window_main


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-mode', choices=['local', 'refresh'], default='local', help='local snapshot by default; refresh explicitly synchronizes; no source-engine fallback')
    parser.add_argument('--source-config', type=Path)
    target = parser.add_mutually_exclusive_group()
    target.add_argument('--conversation-username')
    target.add_argument('--contact-query')
    target.add_argument('--group-query')
    when = parser.add_mutually_exclusive_group()
    when.add_argument('--request')
    when.add_argument('--latest', nargs='?', const=20, type=int, choices=range(1, 101), metavar='N')
    parser.add_argument('--timezone')
    parser.add_argument('--display-limit', type=int, default=50)
    parser.add_argument('--voice-transcripts', action='store_true')
    parser.add_argument('--voice-runtime-root', type=Path)
    parser.add_argument('--voice-python', type=Path)
    parser.add_argument('--configured-images', action='store_true')
    parser.add_argument('--json', action='store_true', help='output is always native JSON')
    # Unsupported historical source-engine capabilities are not CLI options.
    parser.set_defaults(include_related_groups=False, locate_related_groups=False, check_config=False)
    return parser


def main(argv=None):
    return window_main(_parser().parse_args(argv))


def console_main(argv=None):
    from .failure_evidence import console
    return console(main, argv)


from .failure_evidence import _register
_register(_parser, main, console_main)


if __name__ == '__main__':
    raise SystemExit(console_main())
