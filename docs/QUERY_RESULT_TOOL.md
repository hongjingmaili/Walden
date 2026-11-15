# Query result wrapper

`tools/query_result.py` is an optional repository tool for paging output from a local query. It is distributed with the repository and runs alongside an installed Walden package. The direct `wechat-local-window` entry remains available without the wrapper.

## Capture a query

Run from a trusted operator environment using the current installed Skill and classification rules. Define `WINDOW_CLI` as the absolute `window_cli` in the private current profile. Then pass the same profile explicitly to the wrapper.

```sh
PROFILE="${XDG_CONFIG_HOME:-$HOME/.config}/wechat-local/current-source.json"
python3 tools/query_result.py run -- "$WINDOW_CLI" \
  --source-config "$PROFILE" --conversation-username "$CONVERSATION" --latest 20
```

The wrapper resolves the current profile from the operator environment independently of the child arguments. It requires a private current-user profile, the same installation for the Python, window, and reply entries, and the exact configured window executable. It checks the launcher against the installed Walden console entry, its recorded SHA-256 and the configured Python interpreter. A different profile, an executable with the same name in another directory, an unrecorded launcher, or a changed launcher is refused. The trusted inputs are the operator environment, the current profile and its installed package.

The window query runs in explicit `local` mode. Use `--contact-query`, `--group-query`, or `--conversation-username` for the confirmed target. A date request takes one inclusive date range in `YYYY-MM-DD到YYYY-MM-DD` form and uses the profile time zone or a supplied IANA zone. The wrapper disallows abbreviated, unknown, and duplicated options. Images and voice transcripts use configured local media handling. Explicit voice paths, if supplied, must match the configured pair.

For an existing local request, the adjacent installed `wechat-local-sync` also supports `request-status` with an absolute `--request-record` and `request` with a contact query or a bound target reference plus its hash. Both require `--source-config`. The wrapper accepts the read-only forms. Source copy authorization, refresh, and service commands are excluded from its arguments.

## Continue reading the same result

Use the `result_file` reported by the capture. Paging reads the private copy and does not rerun the query.

```sh
python3 tools/query_result.py page --result-file "$RESULT_FILE" --start 21 --count 20
python3 tools/query_result.py page --result-file "$RESULT_FILE" --raw stdout --offset 0 --length 4000
```

A capture records the exact stdout and stderr bytes in a new private directory under the system temporary root. The record binds both streams to their hashes. A page preserves complete messages and returns explicit raw chunks when an item cannot fit the display limit. For a raw continuation, use the returned end offset and unit. Inspect the original exit, business outcome, coverage, observation time, gaps, and omissions before using the output. Local latest is current only through the observation reported by the installed CLI.

The result directory contains private query data. Keep it outside the repository and remove it when no longer needed. The wrapper does not take over source setup, synchronization, service control, or sending.
