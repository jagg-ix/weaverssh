# Terminal-session model

`TerminalSession.tla` models the two concurrency collisions that define the
detached-terminal security boundary:

- a reattach can preempt an `ACTIVE` ghost connection only by incrementing the
  attachment generation; and
- TTL expiry and reattach compete while `DETACHED`, with termination final if
  expiry wins and TTL invalidated if reattach wins.

It also checks that only the current generation can perform a client write,
that a TTL exists only for a detached session, and that `TERMINATED` cannot be
left. Run it with a TLA+ tools JAR:

```bash
java -cp tla2tools.jar tlc2.TLC \
  -config TerminalSession.cfg TerminalSession.tla
```

The Go race tests exercise the corresponding manager implementation; this
model checks every interleaving within the configured finite generation bound.
Deadlock checking is disabled because `TERMINATED` is intentionally a final
state; the invariants assert that it cannot be left.
