# queuewatch

A tiny CLI that tails a job queue and prints a one-line summary whenever a
job changes state. Useful for keeping an eye on a background worker without
opening a dashboard.

## Installation

Download the latest release archive for your platform from the Releases
page, extract it, and place the `queuewatch` binary somewhere on your PATH.
Prebuilt archives are provided for Linux, macOS, and Windows.

If you'd rather build from source, clone the repository and use your
toolchain's normal build command; the project has no unusual build steps.

## Configuration

queuewatch reads a small YAML file on startup. A minimal example:

```yaml
queue:
  backend: redis
  url: redis://localhost:6379/0
poll_interval_seconds: 5
notify:
  on_state_change: true
  on_failure: true
```

`poll_interval_seconds` controls how often the queue is polled; lower values
trade a bit of CPU for lower latency on state-change notifications.

## Usage

Start it pointed at your config file:

```
queuewatch --config ./queuewatch.yaml
```

Output is one line per state transition, formatted as
`<timestamp> <job_id> <old_state> -> <new_state>`. Pipe it into your usual
log aggregator if you want history beyond the terminal scrollback.

## Contributing

Issues and pull requests are welcome. Please include a short description of
the problem or feature, and add a test where practical. There is no formal
style guide beyond "match what's already there."

## License

MIT
