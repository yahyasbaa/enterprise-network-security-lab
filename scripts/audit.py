"""Fail on runtime drift, unhealthy services, exposed ports or missing controls."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def inside(service, *args):
    return run('docker', 'compose', 'exec', '-T', service, *args)


def audit():
    ids = run('docker','compose','ps','-q').split()
    assert len(ids) == 10, f'Expected 10 containers, got {len(ids)}'
    nodes = json.loads(run('docker','inspect', *ids))
    endpoints = {'users':(10,10),'admin':(30,10),'security':(40,20),'web':(50,10),
                 'database':(20,10),'ssh':(30,20),'collector':(40,10),'internet':(60,10)}
    services = {n['Config']['Labels']['com.docker.compose.service']:n for n in nodes}
    assert set(services) == set(endpoints) | {'firewall','suricata'}
    for node in nodes:
        assert node['State']['Running'] and node['State']['Health']['Status'] == 'healthy', node['Name']
        assert not node['HostConfig']['Privileged'], node['Name']
        assert not node['HostConfig']['PortBindings'], f'Host port exposed: {node["Name"]}'
        assert node['HostConfig']['NetworkMode'] != 'host'
        assert all(m['Destination'] != '/var/run/docker.sock' for m in node['Mounts'])
    for service, (vlan, host) in endpoints.items():
        actual = services[service]['NetworkSettings']['Networks']
        assert set(actual) == {f'enslab_vlan{vlan}'}, f'Unexpected network attachment: {service}'
        assert actual[f'enslab_vlan{vlan}']['IPAddress'] == f'10.77.{vlan}.{host}'
        assert inside(service,'nft','--stateless','list','table','inet','endpoint') == inside(service,'cat','/run/endpoint-policy.snapshot'), f'Endpoint firewall drift: {service}'
    router_nets = services['firewall']['NetworkSettings']['Networks']
    assert set(router_nets) == {f'enslab_vlan{v}' for v in (10,20,30,40,50,60)}
    assert all(router_nets[f'enslab_vlan{v}']['IPAddress'] == f'10.77.{v}.254' for v in (10,20,30,40,50,60))
    assert services['suricata']['HostConfig']['NetworkMode'] == 'container:' + services['firewall']['Id']
    nets = json.loads(run('docker','network','inspect', *[f'enslab_vlan{v}' for v in (10,20,30,40,50,60)]))
    for net, vlan in zip(nets, (10,20,30,40,50,60)):
        assert net['Internal'] and not net['EnableIPv6']
        assert net['IPAM']['Config'][0]['Subnet'] == f'10.77.{vlan}.0/24'
        assert net['Options']['com.docker.network.bridge.inhibit_ipv4'] == 'true'
    assert inside('firewall','cat','/proc/sys/net/ipv4/ip_forward') == '1'
    live = inside('firewall','nft','--stateless','list','ruleset')
    expected = inside('firewall','cat','/run/firewall-policy.snapshot')
    assert live == expected, 'Runtime firewall differs from startup policy'
    assert 'queue to 0' in live and 'bypass' not in live
    for service, filename in [('firewall','firewall/policy.nft'),('suricata','suricata/rules/lab.rules'),('suricata','suricata/suricata.yaml'), *[(s,'firewall/endpoint.nft') for s in endpoints]]:
        digest = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
        assert inside(service,'sha256sum','/opt/lab/'+filename).split()[0] == digest, f'Rebuild image after editing {filename}'
    rules = json.loads(inside('suricata','suricatasc','-c','ruleset-stats','/run/suricata-command.socket'))
    assert rules['return'] == 'OK'
    assert sum(s['rules_loaded'] for s in rules['message']) == 10
    assert sum(s['rules_failed'] for s in rules['message']) == 0
    health = json.loads(inside('collector','curl','-fsS','http://127.0.0.1:8080/health'))
    assert health['healthy'], health
    # Only these real services may listen. Docker's embedded resolver is excluded.
    for service, ports in {'web':{80},'database':{5432},'ssh':{22},'collector':{8080},'internet':{80},'users':set(),'admin':set(),'security':set(),'firewall':set()}.items():
        listeners = inside(service,'ss','-H','-lnt').splitlines()
        observed = {int(row.split()[3].rsplit(':',1)[1]) for row in listeners if not row.split()[3].startswith('127.0.0.11:')}
        assert observed == ports, (service, observed, ports)
    print('PASS: 10 healthy containers, 6 isolated networks, zero host ports, expected listeners, firewall unchanged, 10 Suricata rules, healthy collector')


if __name__ == '__main__':
    audit()
