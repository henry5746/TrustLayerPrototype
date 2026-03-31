# TrustLayerPrototype

A macOS command-line tool that monitors application launches in real time and evaluates them against basic security policy rules.

## What It Does

TrustLayerPrototype listens for app launch events using `NSWorkspace` notifications and runs each launched application through a rule engine to determine whether it is policy-compliant.

### Rules Checked

- **Standard install location** — flags apps running outside `/Applications/` or `/System/Applications/`
- **Code signing** — flags apps whose executables are not code-signed (including ad-hoc signatures)

### Output

For every app that launches, the tool prints:

```
Launched: <App Name> | bundleID=<bundle.id> | pid=<PID>
Policy: compliant
```

or, if issues are found:

```
Policy: flags -> Outside standard locations: /path/to/app; Unsigned executable: /path/to/exec
```

## Requirements

- macOS
- Xcode (to build)

## Usage

Build and run the tool in Xcode or via the command line. It will keep running in the background, logging every app launch and its compliance status to stdout.

## Project Structure

```
TrustLayerPrototype/
└── main.swift   # Entry point — observer setup, rule engine, and run loop
```

## Author

Henry Pacheco-Cruz
