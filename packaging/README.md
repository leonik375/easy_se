# easy_se — systemd integration

Run `easy_se_cli` as a system service, one instance per VPN profile, with
the password kept out of unit files and process command lines.

## Install

```bash
# 1. Build & install the binary
cmake -B build && cmake --build build --target easy_se_cli
sudo install -m 0755 build/easy_se_cli /usr/local/bin/easy_se_cli

# 2. Install the systemd template unit
sudo install -m 0644 packaging/systemd/easy-se@.service \
    /etc/systemd/system/easy-se@.service

# 3. Create a profile config directory (0750 keeps it from non-root users)
sudo install -d -m 0750 /etc/easy-se

# 4. Copy the example config under a profile name of your choice (e.g. "work")
sudo install -m 0600 packaging/conf.d/example.conf \
    /etc/easy-se/work.conf
sudoedit /etc/easy-se/work.conf          # set SE_HOST, SE_USER, etc.

# 5. Put the password in a 0600 file (systemd injects it via LoadCredential)
sudo install -m 0600 /dev/null /etc/easy-se/work.pass
sudoedit /etc/easy-se/work.pass          # one line: the password

# 6. Enable & start
sudo systemctl daemon-reload
sudo systemctl enable --now easy-se@work.service

# 7. Watch logs
journalctl -u easy-se@work.service -f
```

The instance name (`work` in the example) is the part after `@` and matches
`/etc/easy-se/<instance>.conf` + `/etc/easy-se/<instance>.pass`.

## Configuration

See `packaging/conf.d/example.conf` for all keys.  The same file format
works outside systemd:

```bash
easy_se_cli --config /etc/easy-se/work.conf
```

Or pass everything via environment variables:

```bash
SE_HOST=vpn.example.com SE_USER=alice SE_PASS=hunter2 easy_se_cli
```

Precedence (later overrides earlier):
1. `--config <path>`
2. `SE_*` environment variables
3. Positional command-line arguments and `--`-flags

## Security notes

- `SE_PASS` in the config file is plaintext — use `SE_PASS_FILE` and the
  `LoadCredential=` line in the unit file instead.  easy_se refuses to read
  password files with group/other read bits set.
- The unit file enables `NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, and a tight `RestrictAddressFamilies` set.
  If you adapt it to run as a non-root user, you'll need
  `AmbientCapabilities=CAP_NET_ADMIN` so the service can open `/dev/net/tun`
  and update routes.
- TLS validation is **on by default** (`SE_VERIFY_CERT=1`).  Only disable
  it for self-signed servers under your direct control — without it the
  tunnel is trivially MITM-able on hostile networks.
