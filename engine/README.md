# cyberrange engine

Catalog-driven log generator. Loads YAML specs from `../catalog/`, renders Jinja2
templates with random/weighted/CIDR/datetime/faker field generators, ships output
to stdout / file / UDP syslog / TCP syslog.

## Install (dev)

```bash
cd engine
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## CLI

```bash
# List all available catalog specs
cyberrange list

# Generate 100 Fortinet FortiOS 7.4 traffic logs to stdout
cyberrange gen --vendor fortinet --product fortios --version 7.4 \
  --log-type traffic.forward --count 100

# Send Sysmon Process-Create events to ELK filebeat (TCP 1514) at 10/sec
cyberrange gen --vendor microsoft --product windows --version 2022 \
  --log-type sysmon.event_id_1 --count 1000 --rate 10 \
  --sink tcp://192.0.2.18:1514

# UDP to Wazuh syslog with custom param
cyberrange gen --vendor fortinet --product fortios --version 7.4 \
  --log-type traffic.forward --count 50 \
  --param src_cidr=192.168.50.0/24 \
  --sink udp://192.0.2.10:514
```

## Run tests

```bash
pytest
```
