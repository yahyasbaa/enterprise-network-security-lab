import json
import pytest
from .lab import execute, probe, compose


@pytest.mark.parametrize('service,address,port', [
    ('users','10.77.50.10',80), ('users','10.77.60.10',80),
    ('internet','10.77.50.10',80), ('web','10.77.20.10',5432),
    ('admin','10.77.30.20',22), ('admin','10.77.20.10',5432),
    ('admin','10.77.50.10',80), ('admin','10.77.40.10',8080),
    ('security','10.77.30.20',22), ('security','10.77.50.10',80),
    ('security','10.77.20.10',5432), ('security','10.77.40.10',8080)])
def test_allowed_connections(service, address, port):
    assert probe(service, address, port) == 0


@pytest.mark.parametrize('service,address,port,control', [
    ('users','10.77.30.20',22,'admin'), ('users','10.77.20.10',5432,'admin'),
    ('users','10.77.40.10',8080,'admin'), ('web','10.77.30.20',22,'admin'),
    ('web','10.77.40.10',8080,'admin'), ('web','10.77.60.10',80,'users'),
    ('internet','10.77.30.20',22,'admin'), ('internet','10.77.20.10',5432,'admin'),
    ('internet','10.77.40.10',8080,'admin'), ('database','10.77.50.10',80,'users'),
    ('database','10.77.30.20',22,'admin'), ('collector','10.77.50.10',80,'users'),
    ('security','10.77.60.10',80,'users')])
def test_forbidden_connections_timeout_not_closed(service, address, port, control):
    assert probe(control, address, port) == 0, 'Positive control must prove listener is up'
    assert probe(service, address, port) == 10, 'Must DROP; refusal is not isolation'


@pytest.mark.parametrize('port', [22,443,5432,8080])
def test_untrusted_only_http_exposed(port):
    assert probe('internet', '10.77.50.10', port) == 10


@pytest.mark.parametrize('service', ['users','admin','security','web','database','ssh','collector','internet'])
def test_no_external_route_or_dns(service):
    assert 'default' not in execute(service, 'ip', 'route').stdout
    assert execute(service, 'cat', '/etc/resolv.conf').stdout.startswith('nameserver 127.0.0.1')
    # Read-only route lookup, never send a packet outside the lab.
    assert execute(service, 'ip', 'route', 'get', '192.0.2.1', check=False).returncode != 0
    assert execute(service, 'cat', '/proc/sys/net/ipv6/conf/all/disable_ipv6').stdout.strip() == '1'


def test_nginx_http_content_and_basic_auth():
    body = execute('users', 'curl', '-fsS', 'http://10.77.50.10/').stdout
    assert 'Enterprise Network Security Lab' in body
    assert execute('users','curl','-s','-o','/dev/null','-w','%{http_code}', 'http://10.77.50.10/private').stdout == '401'
    authenticated = execute('admin','sh','-c',
                            'curl -fsS -u "analyst:$(cat /run/secrets/web_password)" http://10.77.50.10/private')
    assert 'Enterprise Network Security Lab' in authenticated.stdout


def test_ssh_real_key_authentication():
    result = execute('admin','ssh','-i','/run/secrets/admin_key','-o','StrictHostKeyChecking=no',
                     '-o','UserKnownHostsFile=/dev/null','-o','BatchMode=yes',
                     'labadmin@10.77.30.20','id -un')
    assert result.stdout.strip() == 'labadmin'


def test_database_real_authenticated_query_from_dmz():
    result = execute('web','sh','-c', 'PGPASSWORD="$(cat /run/secrets/db_password)" psql -h 10.77.20.10 -U labapp -d lab -Atc "SELECT count(*) FROM inventory"')
    assert result.stdout.strip() == '2'


def test_runtime_no_host_ports_and_isolated_bridges():
    ids = compose('ps','-q').stdout.split()
    import subprocess
    nodes = json.loads(subprocess.check_output(['docker','inspect',*ids]))
    assert len(nodes) == 10
    for node in nodes:
        assert not node['HostConfig']['PortBindings']
        assert not node['HostConfig']['Privileged']
        assert node['State']['Health']['Status'] == 'healthy'
    nets = json.loads(subprocess.check_output(['docker','network','inspect',*[f'enslab_vlan{n}' for n in (10,20,30,40,50,60)]]))
    assert all(n['Internal'] and not n['EnableIPv6'] for n in nets)
    assert all(n['Options']['com.docker.network.bridge.inhibit_ipv4'] == 'true' for n in nets)
