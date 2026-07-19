# Configuration

Noirpass stores configuration in `config.toml` inside its data directory.

Default location:

```text
$XDG_DATA_HOME/noirpass/config.toml
```

When `XDG_DATA_HOME` is unset:

```text
~/.local/share/noirpass/config.toml
```

With `--store-dir /path/to/store` or `NOIRPASS_STORE=/path/to/store`, configuration is at
`/path/to/store/config.toml`.

`noirpass init --recipient <FILE|->` creates configuration with secure file permissions. Recipient
fields are managed by Noirpass; edit only documented runtime settings.

## Idle Exit

```toml
idle_exit = 300
```

`idle_exit` controls how daemon exits when no sessions remain:

|            Value | Behavior                                                           |
| ---------------: | ------------------------------------------------------------------ |
|             `-1` | Keep daemon running until signal or fatal store error              |
|              `0` | Exit after first completed Noirpass handler                        |
| Positive integer | Exit after this many seconds without Noirpass application activity |

Default is `300`. Existing configuration without `idle_exit` uses same default. Re-running
`noirpass init` preserves current deserialized value. Command-line `--idle-exit <VALUE>` overrides
configuration for one invocation.

With `idle_exit = 0`, exit occurs after first completed Noirpass application method or property
handler, once no handler is active and no session is open. Calls managed directly by zbus, including
`org.freedesktop.DBus.Peer.Ping` and `org.freedesktop.DBus.Introspectable.Introspect`, do not count
as Noirpass application activity.

Examples:

```toml
# Exit after first Noirpass handler finishes and no session remains.
idle_exit = 0
```

```toml
# Keep daemon running.
idle_exit = -1
```

```toml
# Exit after ten inactive minutes.
idle_exit = 600
```
