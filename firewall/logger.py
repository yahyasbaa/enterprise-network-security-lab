"""Decode NFLOG pcap records from libpcap; retain the kernel's rule prefix."""
import datetime
import ipaddress
import json
import struct
import subprocess


def read_exact(stream, count):
    data = b''
    while len(data) < count:
        chunk = stream.read(count - len(data))
        if not chunk:
            raise EOFError('NFLOG capture terminated')
        data += chunk
    return data


def decode(data, timestamp):
    # DLT_NFLOG: nfgen header, then native-endian, 4-byte-aligned nlattrs.
    attributes = {}
    offset = 4
    while offset + 4 <= len(data):
        length, kind = struct.unpack_from('=HH', data, offset)
        if length < 4 or offset + length > len(data):
            raise ValueError('Malformed NFLOG attribute')
        attributes[kind & 0x3fff] = data[offset + 4:offset + length]
        offset += (length + 3) & ~3
    prefix = attributes.get(10, b'').rstrip(b'\x00').decode().strip()
    payload = attributes.get(9, b'')
    if not prefix or len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    rule_id, action = prefix.split(maxsplit=1)
    proto = payload[9]
    header = (payload[0] & 15) * 4
    sport, dport = struct.unpack_from('!HH', payload, header) if proto in (6,17) and len(payload) >= header + 4 else (0,0)
    return dict(timestamp=timestamp, source='firewall', rule_id=rule_id, action=action,
                src_ip=str(ipaddress.IPv4Address(payload[12:16])),
                dest_ip=str(ipaddress.IPv4Address(payload[16:20])), src_port=sport,
                dest_port=dport, proto={6:'TCP',17:'UDP',1:'ICMP'}.get(proto,str(proto)),
                prefix=prefix, packet_length=len(payload))


def main():
    process = subprocess.Popen(['tcpdump','-U','-s','0','-i','nflog:5','-w','-'], stdout=subprocess.PIPE)
    stream = process.stdout
    header = read_exact(stream, 24)
    endian = '<' if header[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    if struct.unpack_from(endian+'I', header, 20)[0] != 239:
        raise ValueError('Expected DLT_NFLOG')
    with open('/logs/firewall/events.jsonl','a',buffering=1) as output:
        while True:
            sec, usec, length, original = struct.unpack(endian+'IIII',read_exact(stream,16))
            stamp = datetime.datetime.fromtimestamp(sec+usec/1e6,datetime.timezone.utc).isoformat()
            event = decode(read_exact(stream,length),stamp)
            if event:
                output.write(json.dumps(event)+'\n')


if __name__ == '__main__':
    main()
