# Docker Network Isolation

Control network access for Docker Compose containers using iptables.

### Modes

| Mode | Internet | LAN/Host |
|------|----------|----------|
| `block-internet` | Blocked | Allowed |
| `block-lan` | Allowed | Blocked |
| `block-all` | Blocked | Blocked |
| `unblock` | Allowed | Allowed |

Port-forwarded connections always work regardless of mode.

### Usage

```
docker-network-isolation.sh {block-internet|block-lan|block-all|unblock|status}

  block-internet  - Block internet access, allow LAN/host
  block-lan       - Block LAN/host access, allow internet
  block-all       - Block both internet and LAN/host access
  unblock         - Remove all isolation rules
  status          - Show current network isolation state
```

### Docker compose

docker-compose.yaml has to contain a subnet configuration. Something like this should work:

```yaml
services:
  some_service:
    [...]
    networks:
      - my-isolated-network

networks:
  my-isolated-network:
    driver: bridge
    ipam:
      config:
        - subnet: 10.255.0.0/16
          gateway: 10.255.0.1
```


## License

Whatever
