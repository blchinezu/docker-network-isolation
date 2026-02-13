# Docker Network Isolation

Control network access for Docker Compose containers using iptables.

## Modes

| Mode | Internet | LAN/Host |
|------|----------|----------|
| `block-internet` | Blocked | Allowed |
| `block-lan` | Allowed | Blocked |
| `block-all` | Blocked | Blocked |
| `unblock` | Allowed | Allowed |

Port-forwarded connections always work regardless of mode.

## Usage

```
Usage: docker-network-isolation.sh {block-internet|block-lan|block-all|unblock|status}

  block-internet  - Block internet access, allow LAN/host
  block-lan       - Block LAN/host access, allow internet
  block-all       - Block both internet and LAN/host access
  unblock         - Remove all isolation rules
  status          - Show current network isolation state
```

Requires `sudo` and `iptables`.

## License

Whatever
