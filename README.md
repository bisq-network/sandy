# sandy

sandy runs a program inside an operating system sandbox on Linux, macOS and Windows. A small policy
lists the paths the program may read, execute or write, and whether it may use the network. Everything
else is denied. If the host cannot enforce the policy, sandy refuses to start the program.

Status: under development, not ready for use.

```sh
sandy run \
  --read-exec /opt/app/bin \
  --read-write /var/lib/app \
  --ip all \
  -- /opt/app/bin/app --flag
```

`sandy check` shows how the current host enforces a policy. See [docs/DESIGN.md](docs/DESIGN.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
