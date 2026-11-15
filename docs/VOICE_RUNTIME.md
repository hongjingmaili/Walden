# Local voice runtime (0.6.1)

The wheel includes the local adapter and dependency-preparation helper, not pilk, whisper.cpp binaries/libraries or a model. Preparing these dependencies never authorizes a WeChat key/database read, a query, a client start or a send.

Use a **new private ASR Python environment and new runtime root**. Do not run the helper against the stable application/747 Python: it installs build tools into the supplied environment. The helper refuses to overwrite an existing runtime root. Do not guess a runtime location from historical defaults; the operator must supply the exact pair and save a preparation receipt.

The included `resources/tools/install_local_voice_runtime.sh` accepts `/absolute/asr-venv/bin/python /absolute/new/runtime-root`. It builds pilk locally and downloads a source archive and the fixed multilingual small model. It requires network access, Xcode Command Line Tools, curl, tar, shasum and the new Python/pip. Review and prepare it separately from message queries. Its existing pins are:

- pilk 0.2.4 from [PyPI](https://pypi.org/project/pilk/0.2.4/), sdist SHA256 `d4a1bcf93dc6ef5e95e0cfd728ed4ef4d49f9c0476d70816fecbe456cc762e7f`;
- typing-extensions 4.16.0, wheel SHA256 `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8`;
- whisper.cpp v1.9.5 source archive at `https://github.com/ggml-org/whisper.cpp/archive/refs/tags/v1.9.5.tar.gz`, archive SHA256 `ff1a9053feb509ff9d7729703355541ae9690073a6b1c40eb692c962e0dc1720`; its prior archive build reported `whisper.cpp version: 1.9.5-dev`. Availability and actual binary/version/library closure still require preparation-time verification; an archive hash is not a binary hash;
- [ggml-small.bin](https://huggingface.co/ggerganov/whisper.cpp/blob/main/ggml-small.bin), **487601967 bytes**, SHA256 `1be3a9b2063867b937e64e2ec7483364a79917e157fa98c5d94b5c1fffea987b`. Model data remains local. Download URL `https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-small.bin` is mutable by name; the adapter and helper enforce the content hash.

Runtime layout remains:

```text
runtime-root/
  python/pilk/
  whisper.cpp/build/bin/whisper-cli
  downloads/ggml-small.bin
```

Record the exact Python ABI, pilk distribution, decoder ABI, recognizer binary SHA and reported version, required libraries, and model size/SHA. Pair absolute `voice_runtime_root` and `voice_python` in the same authorized source profile using a reviewed mechanical profile update; no setup/rekey is needed. Set a bounded `media_transcriber_version` identifying that prepared pipeline. Update it when changing the decoder/model/recognizer; do not update it just for restart/query. This is an explicit cache version, not automatic detection of arbitrary in-place binary replacement.

The owned background media child retains SILK and saves a mono 16-bit 24kHz WAV **before** local ASR. WAV preparation requires only Python/pilk; a missing model/recognizer does not remove playable audio. ASR reuses the saved WAV. Transcripts are persisted by audio content SHA and pipeline version with model/recognizer provenance. Finite retries and pending/failed states are separate from message-copy completion and playback readiness.

`window_cli --source-config ... --voice-transcripts --voice-jsonl` reads only the already copied media and cached text. Runtime arguments retained for compatibility do not request query-time ASR. Queries do not probe the runtime/model, decode, queue work, read a key or open Source databases. Native packed transcripts take precedence and are labelled separately from local recognition. The Skill presents the returned local WAV link, cached text and exact pending/failed reason without refreshing to retry.

The adapter uses the explicitly configured Python in isolated mode and adds only the selected runtime's python directory. Audio/model/temporary decode files remain local and private. Accuracy and support for every audio/environment are not guaranteed. No dependency was installed or downloaded as part of the 0.6.1 synthetic candidate tests.

## License/source notes

The candidate license and adapted SQLCipher/WCDB notice remain in THIRD_PARTY_NOTICES and licenses. pilk is separately obtained GPL-3.0 with its sdist LICENSE; typing-extensions declares PSF-2.0; whisper.cpp and the model card declare MIT. CMake is a separate build-time dependency. These downloads and built tools/model are not redistributed in this wheel; its own notices do not change their separate licenses.
