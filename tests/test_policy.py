import subprocess
from .lab import ROOT, execute


def test_runtime_security_audit():
    result = subprocess.run(['python3','scripts/audit.py'], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_endpoint_service_processes_drop_network_capabilities():
    # PID 1 is tini and retains bootstrap caps; inspect the actual service tree.
    for service in ('web','database','ssh','collector','internet','users','admin','security'):
        result = execute(service,'python3','-c', '''from pathlib import Path
for path in Path('/proc').glob('[0-9]*/status'):
 text=path.read_text()
 name=text.splitlines()[0].split()[1]
 if name in ('nginx','postgres','sshd','python3','sleep') and int(path.parent.name)>1:
  caps=int(next(x.split()[1] for x in text.splitlines() if x.startswith('CapBnd:')),16)
  if name=='python3' and b'-c' in (path.parent/'cmdline').read_bytes().split(b'\\0'): continue
  assert not caps & ((1<<12)|(1<<13)), (name,caps)
''')
        assert result.returncode == 0


def test_ingress_rejects_cross_vlan_source_spoofing():
    from .lab import watermark, wait_events
    after = watermark()
    # Nmap cannot select a route for a source IP absent from this container.
    # Send one fixed local IPv4 packet through the kernel's destination route.
    execute('users','python3','-c', '''import socket,struct
src=socket.inet_aton('10.77.50.10'); dst=socket.inet_aton('10.77.20.10')
tcp=struct.pack('!HHLLBBHHH',45000,5432,1,0,80,2,1024,0,0)
pseudo=src+dst+struct.pack('!BBH',0,6,len(tcp))+tcp
total=sum(struct.unpack('!%dH'%(len(pseudo)//2),pseudo))
while total>>16: total=(total&65535)+(total>>16)
tcp=tcp[:16]+struct.pack('!H',~total&65535)+tcp[18:]
ip=struct.pack('!BBHHHBBH4s4s',69,0,40,1234,0,64,6,0,src,dst)
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.sendto(ip+tcp,('10.77.20.10',0));s.close()
''')
    wait_events(after,'firewall',lambda e: e['raw'].get('rule_id') == 'F01'
                and e['src_ip'] == '10.77.50.10' and e['dest_ip'] == '10.77.20.10')
