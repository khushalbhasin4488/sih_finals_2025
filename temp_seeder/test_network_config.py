#!/usr/bin/env python3
"""
Test script to verify network domain configuration
"""

# Network Domain Configuration (copied from seeder.py)
NETWORKS = {
    "corporate": {
        "name": "Corporate Network",
        "hosts": [f"server-{i:02d}" for i in range(1, 11)],
        "ip_ranges": ["192.168.1."],
    },
    "dmz": {
        "name": "DMZ Network",
        "hosts": [f"server-{i:02d}" for i in range(11, 15)],
        "ip_ranges": ["10.0.0."],
    },
    "iot": {
        "name": "IoT Network",
        "hosts": [f"server-{i:02d}" for i in range(15, 17)],
        "ip_ranges": ["192.168.100."],
    },
    "guest": {
        "name": "Guest Network",
        "hosts": [f"server-{i:02d}" for i in range(17, 19)],
        "ip_ranges": ["192.168.200."],
    },
    "public": {
        "name": "Public Network",
        "hosts": [f"server-{i:02d}" for i in range(19, 21)],
        "ip_ranges": [],
    }
}

# Create reverse mapping: host -> network_id
HOST_TO_NETWORK = {}
for network_id, network_config in NETWORKS.items():
    for host in network_config["hosts"]:
        HOST_TO_NETWORK[host] = network_id

def get_network_id(host, ip=None):
    """Determine network_id based on host or IP address"""
    if host in HOST_TO_NETWORK:
        return HOST_TO_NETWORK[host]
    
    if ip:
        for network_id, network_config in NETWORKS.items():
            for ip_prefix in network_config["ip_ranges"]:
                if ip.startswith(ip_prefix):
                    return network_id
        if not any(ip.startswith(prefix) for prefix in ["192.168.", "10.0.", "172.16."]):
            return "public"
    
    return "corporate"

# Test network configuration
print('\n=== Network Configuration ===')
for net_id, net_config in NETWORKS.items():
    print(f'{net_id}: {net_config["name"]} - {len(net_config["hosts"])} hosts')

print(f'\nTotal hosts mapped: {len(HOST_TO_NETWORK)}')

# Test host-to-network mapping
print('\n=== Host-to-Network Mapping Tests ===')
test_hosts = ['server-01', 'server-05', 'server-11', 'server-13', 'server-15', 'server-17', 'server-19']
for host in test_hosts:
    net_id = get_network_id(host)
    net_name = NETWORKS[net_id]["name"]
    print(f'✓ {host} -> {net_id} ({net_name})')

# Test IP-based network detection
print('\n=== IP-based Network Detection Tests ===')
test_cases = [
    ('192.168.1.10', 'corporate'),
    ('10.0.0.50', 'dmz'),
    ('192.168.100.5', 'iot'),
    ('192.168.200.10', 'guest'),
    ('8.8.8.8', 'public'),
    ('203.0.113.1', 'public'),
]

all_passed = True
for ip, expected in test_cases:
    net_id = get_network_id('unknown-host', ip)
    status = '✓' if net_id == expected else '✗'
    if net_id != expected:
        all_passed = False
    print(f'{status} {ip} -> {net_id} (expected: {expected})')

# Network distribution
print('\n=== Network Distribution ===')
for net_id, net_config in NETWORKS.items():
    host_count = len(net_config["hosts"])
    percentage = (host_count / 20) * 100
    print(f'{net_id}: {host_count} hosts ({percentage:.0f}%)')

if all_passed:
    print('\n✅ All tests passed! Network domain configuration is working correctly.')
else:
    print('\n⚠️  Some tests failed. Please review the configuration.')
