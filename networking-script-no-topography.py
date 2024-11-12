import requests
import json
from prettytable import PrettyTable

# Read API keys and organization IDs from the file
api_keys_org_ids_file = 'api_keys_org_ids.txt'
with open(api_keys_org_ids_file, 'r') as file:
    data = file.readline().strip().split(',')
    api_key = data[0]
    org_id = data[1]

# Define the base URL for the Meraki API
base_url = 'https://api.meraki.com/api/v1'

# Set up the headers for the API request
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Cisco-Meraki-API-Key': api_key
}

# Function to get organization information
def get_organization_info(org_id):
    url = f'{base_url}/organizations/{org_id}'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve organization info (Status Code: {response.status_code})")
        return None

# Function to get network list for an organization
def get_networks(org_id):
    url = f'{base_url}/organizations/{org_id}/networks'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve networks (Status Code: {response.status_code})")
        return []

# Function to get device inventory for an organization
def get_device_inventory(org_id):
    url = f'{base_url}/organizations/{org_id}/inventory/devices'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve device inventory (Status Code: {response.status_code})")
        return []

# Function to get all details for a specific device (with caching)
device_cache = {}
def get_device_details(network_id, device_id):
    if device_id in device_cache:
        return device_cache[device_id]
    url = f'{base_url}/networks/{network_id}/devices/{device_id}'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        device_cache[device_id] = response.json()
        return device_cache[device_id]
    elif response.status_code == 404:
        return None  # Skip logging 404 errors to avoid cluttering output
    else:
        print(f"Error: Could not retrieve details for device {device_id} (Status Code: {response.status_code})")
        return None

# Function to get raw network configuration details
def get_network_details(network_id):
    url = f'{base_url}/networks/{network_id}'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve details for network {network_id} (Status Code: {response.status_code})")
        return None

# Function to get VLAN settings for a network
def get_network_vlan_settings(network_id):
    url = f'{base_url}/networks/{network_id}/appliance/vlans'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve VLAN settings for network {network_id} (Status Code: {response.status_code})")
        return None

# Function to get uplink settings for a device
def get_device_uplink_settings(device_id):
    url = f'{base_url}/devices/{device_id}/appliance/uplinks/settings'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve uplink settings for device {device_id} (Status Code: {response.status_code})")
        return None

# Function to get DHCP subnet information for a device
def get_device_dhcp_subnets(device_id):
    url = f'{base_url}/devices/{device_id}/appliance/dhcp/subnets'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve DHCP subnets for device {device_id} (Status Code: {response.status_code})")
        return None

# Function to get switch port statuses for a device
def get_switch_port_statuses(device_id):
    url = f'{base_url}/devices/{device_id}/switch/ports/statuses'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve switch port statuses for device {device_id} (Status Code: {response.status_code})")
        return []

# Function to get license information for the organization
def get_organization_licenses(org_id):
    url = f'{base_url}/organizations/{org_id}/licensing/coterm/licenses'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not retrieve license information (Status Code: {response.status_code})")
        return []

# Function to map device relationships using LLDP/CDP
def map_device_relationships(devices):
    relationships = {}  # key: parent_device_id, value: list of connected devices
    device_serial_map = {device['serial']: device for device in devices}
    
    # Initialize the relationship mapping
    for device in devices:
        relationships[device['serial']] = []

    # Go through each switch and analyze LLDP/CDP to determine connections
    for device in devices:
        if 'ms' in device.get('model', '').lower():  # Check if the device is a switch
            port_statuses = get_switch_port_statuses(device['serial'])
            for port in port_statuses:
                # Check if LLDP or CDP information is available
                if port.get('lldp') or port.get('cdp'):
                    connected_info = port.get('lldp') or port.get('cdp')
                    connected_device_serial = connected_info.get('deviceId')  # This could be different, depending on API
                    if connected_device_serial and connected_device_serial in device_serial_map:
                        relationships[device['serial']].append(connected_device_serial)
                        relationships[connected_device_serial] = relationships.get(connected_device_serial, [])
    
    return relationships

# Function to display firewalls, switches, and access points in pretty tables based on each site
def display_pretty_tables_by_site(networks, devices):
    relationships = map_device_relationships(devices)
    device_serial_map = {device['serial']: device for device in devices}
    for network in networks:
        network_id = network.get('id')
        network_name = network.get('name', 'Unknown Site')
        network_devices = [device for device in devices if device.get('networkId') == network_id]

        if not network_devices:
            print(f"\nNo devices found for site: {network_name}")
            continue

        print(f"\nSite: {network_name}")

        # Display VLAN settings
        vlan_settings = get_network_vlan_settings(network_id)
        if vlan_settings:
            vlan_table = PrettyTable()
            vlan_table.field_names = ["VLAN ID", "Name", "Subnet", "Appliance IP"]
            for vlan in vlan_settings:
                vlan_table.add_row([
                    vlan.get('id', 'N/A'),
                    vlan.get('name', 'N/A'),
                    vlan.get('subnet', 'N/A'),
                    vlan.get('applianceIp', 'N/A')
                ])
            print("\nVLAN Settings:")
            print(vlan_table)

        firewalls = [device for device in network_devices if 'mx' in device.get('model', '').lower()]
        switches = [device for device in network_devices if 'ms' in device.get('model', '').lower()]
        access_points = [device for device in network_devices if 'mr' in device.get('model', '').lower()]

        # Firewalls Table
        if firewalls:
            firewall_table = PrettyTable()
            firewall_table.field_names = ["Name", "Model", "MAC Address", "LAN IP", "Firmware", "Uplink Settings"]
            for firewall in firewalls:
                firewall_details = get_device_details(firewall['networkId'], firewall['serial'])
                uplink_settings = get_device_uplink_settings(firewall['serial'])
                uplink_info = "\n".join([
                    f"WAN1: Enabled: {uplink_settings['interfaces']['wan1'].get('enabled', 'N/A')}, "
                    f"VLAN Tagging: {uplink_settings['interfaces']['wan1']['vlanTagging'].get('enabled', 'N/A')}, "
                    f"IPv4 Assignment Mode: {uplink_settings['interfaces']['wan1']['svis']['ipv4'].get('assignmentMode', 'N/A')}, "
                    f"IPv4 Address: {uplink_settings['interfaces']['wan1']['svis']['ipv4'].get('address', 'N/A')}, "
                    f"IPv4 Gateway: {uplink_settings['interfaces']['wan1']['svis']['ipv4'].get('gateway', 'N/A')}"
                ]) if uplink_settings else 'N/A'
                if firewall_details:
                    firewall_table.add_row([
                        firewall.get('name', 'N/A'),
                        firewall.get('model', 'N/A'),
                        firewall_details.get('mac', 'N/A'),
                        firewall_details.get('lanIp', 'N/A'),
                        firewall_details.get('firmware', 'N/A'),
                        uplink_info
                    ])
            print("\nFirewalls:")
            print(firewall_table)
        else:
            print("\nNo firewalls found.")

        # Switches Table
        if switches:
            switch_table = PrettyTable()
            switch_table.field_names = ["Name", "Model", "MAC Address", "LAN IP", "Firmware"]
            for switch in switches:
                switch_details = get_device_details(switch['networkId'], switch['serial'])
                if switch_details:
                    switch_table.add_row([
                        switch.get('name', 'N/A'),
                        switch.get('model', 'N/A'),
                        switch_details.get('mac', 'N/A'),
                        switch_details.get('lanIp', 'N/A'),
                        switch_details.get('firmware', 'N/A')
                    ])
            print("\nSwitches:")
            print(switch_table)

            # Display Switch Port Statuses
            for switch in switches:
                port_statuses = get_switch_port_statuses(switch['serial'])
                if port_statuses:
                    port_table = PrettyTable()
                    port_table.field_names = ["Port ID", "Status", "Speed", "Duplex", "Errors", "Warnings", "LLDP/CDP Info"]
                    for port in port_statuses:
                        lldp_cdp_info = []
                        if 'lldp' in port:
                            lldp_info = port['lldp']
                            lldp_cdp_info.append(f"LLDP: System Name: {lldp_info.get('systemName', 'N/A')}, Port ID: {lldp_info.get('portId', 'N/A')}")
                        if 'cdp' in port:
                            cdp_info = port['cdp']
                            lldp_cdp_info.append(f"CDP: System Name: {cdp_info.get('systemName', 'N/A')}, Port ID: {cdp_info.get('portId', 'N/A')}")
                        port_table.add_row([
                            port.get('portId', 'N/A'),
                            port.get('status', 'N/A'),
                            port.get('speed', 'N/A'),
                            port.get('duplex', 'N/A'),
                            ', '.join(port.get('errors', [])),
                            ', '.join(port.get('warnings', [])),
                            '; '.join(lldp_cdp_info)
                        ])
                    print(f"\nPort Statuses for Switch: {switch.get('name', 'N/A')} ({switch.get('model', 'N/A')}):")
                    print(port_table)
        else:
            print("\nNo switches found.")

        # Access Points Table
        if access_points:
            ap_table = PrettyTable()
            ap_table.field_names = ["Name", "Model", "MAC Address", "LAN IP", "Firmware"]
            for ap in access_points:
                ap_details = get_device_details(ap['networkId'], ap['serial'])
                if ap_details:
                    ap_table.add_row([
                        ap.get('name', 'N/A'),
                        ap.get('model', 'N/A'),
                        ap_details.get('mac', 'N/A'),
                        ap_details.get('lanIp', 'N/A'),
                        ap_details.get('firmware', 'N/A')
                    ])
            print("\nAccess Points:")
            print(ap_table)
        else:
            print("\nNo access points found.")

        # Display ASCII Topology
        display_ascii_topology(network_name, relationships, firewalls, device_serial_map)

# Function to display ASCII topology diagram
def display_ascii_topology(site_name, relationships, root_devices, device_serial_map):
    print(f"\nASCII Topology for Site: {site_name}")
    print("\n+---------[ Network Topology ]---------+")

    def display_hierarchy(device_id, level=0):
        prefix = "    " * level + "|-- "
        device = device_serial_map.get(device_id, {})
        device_name = device.get('name', 'Unknown Device')
        print(f"{prefix}[{device.get('model', 'Device')}] {device_name}")
        for child_id in relationships.get(device_id, []):
            display_hierarchy(child_id, level + 1)

    # Start from root devices (typically firewalls)
    for root_device in root_devices:
        display_hierarchy(root_device['serial'])

    print("+-------------------------------------+")

# Function to display networks table
def display_networks_table(networks):
    table = PrettyTable()
    table.field_names = ["Network ID", "Name", "Type", "Tags"]
    for network in networks:
        table.add_row([network.get('id', 'N/A'), network.get('name', 'N/A'), network.get('type', 'N/A'), ', '.join(network.get('tags', []) or ['N/A'])])
    print("\nNetworks:")
    print(table)

# Main script
networks = get_networks(org_id)
devices = get_device_inventory(org_id)

if networks:
    display_networks_table(networks)
    display_pretty_tables_by_site(networks, devices)
else:
    print("No networks found.")
