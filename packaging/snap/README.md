# Snap Packaging

weaverssh Snap support is generated from an already-built Linux `wv` binary. The
Snap project installs a single app, `wv`, and keeps Snap packaging separate from
runtime behavior.

Generate the Snap project without requiring `snapcraft`:

```sh
make build-linux
make package-snap-project SNAP_ARCH=amd64
```

The generated project is written to `dist/snap/weaverssh/`:

```text
dist/snap/weaverssh/snap/snapcraft.yaml
dist/snap/weaverssh/payload/bin/wv
```

Build a `.snap` on a Linux host with Snapcraft installed:

```sh
make package-snap SNAP_ARCH=amd64
```

Expected artifact:

```text
dist/snap/weaverssh_0.1.0-1_amd64.snap
```

The default confinement is `strict` and the default app plugs are `home`,
`network`, `network-bind`, `removable-media`, `ssh-keys`, and `x11`. Use extra
`SNAP_PLUG_ARGS="--plug <name>"` only when a specific workflow requires an
additional declared interface.
