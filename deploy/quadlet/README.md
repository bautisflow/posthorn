# Podman Quadlet unit

Run Posthorn as a systemd-managed Podman container.

## Files

- `posthorn.container` — the Quadlet unit
- `posthorn.env.example` — provider credentials template

## Install (rootless)

```bash
mkdir -p ~/posthorn ~/.config/containers/systemd

cp posthorn.container ~/.config/containers/systemd/
cp posthorn.env.example ~/posthorn/posthorn.env   # then edit + chmod 600
# place your config at ~/posthorn/posthorn.toml

systemctl --user daemon-reload
systemctl --user start posthorn
loginctl enable-linger "$USER"     # keep running after logout
```

For a system-wide install, put the files under `/etc/containers/systemd/` and
`/etc/posthorn/`, replace the `%h` paths in the unit with absolute ones, and run
`systemctl` without `--user`.

See the [Podman deployment docs](https://posthorn.dev/deployment/podman/) for the
full walkthrough, including the SELinux `:Z` requirement and rootless-networking
notes.
