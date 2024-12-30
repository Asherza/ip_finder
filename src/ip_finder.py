import nmap
import tomlkit
from pathlib import Path
from dataclasses import dataclass

# args
NMAP_ARGS = '-sn --privileged'


# Host dataclass used to hold some common data
@dataclass
class Host:
    name: str
    ip: str
    mac: str


class IPFinder():

    def __init__(self, input_file: str, nmap_host: str):
        self._hosts = []

        # Parse Toml
        self._path = Path(input_file)
        self._parse_toml(self._path, self._hosts)

        # Run initial scan
        self._nmap_host = nmap_host
        self._nm = nmap.PortScanner()

    # Takes in toml and creates any namedtuples based on the toml file
    def _parse_toml(self, _path: Path, _hosts: list):
        data = None
        with open(_path, "rb") as f:
            data = tomlkit.loads(f.read())
            # build our hosts lists from the toml
            [_hosts.append(Host(
                entry[0], entry[1].get('ip'), entry[1].get('mac'))) for entry in data.items()]

    # Does an map scan and attempts to map any hosts found in the hosts list, and populates them
    def scan(self):
        scan = self._nm.scan(hosts=self._nmap_host, arguments=NMAP_ARGS)
        print(scan)
        for ip, address in scan['scan'].items():
            # Find if we have a matching entry
            match = list(filter(lambda x: x.mac ==
                         address['addresses'].get('mac'), self._hosts))
            print(match)
            # Match found, assign IP!
            if len(match) > 0:
                match = match.pop()
                match.ip = ip

    def dump_hosts(self, file=None):
        if file is None:
            file = self._path

        # Load in any toml from the file given
        toml = None
        with open(file, "rb") as f:
            toml = tomlkit.loads(f.read())
        print(self._hosts)
        # Update any hosts found in file with an IP that was found
        for host in self._hosts:
            if ip := host.ip:
                toml[host.name]['ip'] = ip

        # Write to file
        with open(file, mode="wt", encoding="utf-8") as f:
            tomlkit.dump(toml, f)

    def get_hosts(self):
        return self._hosts


ip_finder = IPFinder("test.toml", '192.168.1.0/24')
ip_finder.scan()
ip_finder.dump_hosts()
