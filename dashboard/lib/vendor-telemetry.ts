// dashboard/lib/vendor-telemetry.ts
/**
 * Generates vendor-specific Running Configurations
 */
export function generateVendorConfig(hostname: string, vendorType: string): string {
  const norm = (vendorType || '').toLowerCase().replace(/[^a-z0-9_]/g, '');

  // Aruba / HPE (ArubaOS-CX)
  if (norm.includes('aruba') || norm.includes('aoscx')) {
    return `hostname ${hostname}
!
user admin group administrators password ciphertext $6$rounds=100000$ArubaPass123!
!
ssh server vrf default
no https-server http-enable
!
interface 1/1/1
   no shutdown
   description Uplink to Spine-01
   ip address 10.100.1.1/30
!
router bgp 65001
   bgp router-id 10.255.0.1
   neighbor 10.100.1.2 remote-as 65000`;
  }

  // Huawei (VRP / CloudEngine)
  if (norm.includes('huawei') || norm.includes('vrp')) {
    return `#
sysname ${hostname}
#
aaa
 local-user admin password reversible-cipher PlainAdminHuawei123
 local-user admin privilege level 15
 local-user admin service-type ssh telnet terminal
#
telnet server enable
#
interface 10GE1/0/1
 description DC-Interconnect-Link
 undo portswitch
 ip address 172.16.10.1 255.255.255.252
#
return`;
  }

  // Dell Technologies (Dell OS10)
  if (norm.includes('dell') || norm.includes('os10')) {
    return `hostname ${hostname}
!
username admin password $6$DellSalt$HashPass123 role sysadmin priv-lvl 15
!
interface ethernet1/1/1
 description Uplink-Core-Switch
 no switchport
 ip address 192.168.100.1/30
 no shutdown
!
management telnet-server enable
!
ip route 0.0.0.0/0 192.168.100.2`;
  }

  if (norm.includes('arista') || norm.includes('eos')) {
    return `hostname ${hostname}
!
transceiver qsfp default-mode 4x10G
!
no aaa root
!
username admin privilege 15 role network-admin secret sha512 $6$eXampLeHash
!
management api http-commands
   protocol http
   no shutdown
!
management telnet
   no shutdown
!
interface Ethernet1
   description Core Link to Leaf-02
   no switchport
   ip address 10.0.0.1/30
!
ip route 0.0.0.0/0 10.0.0.2`;
  }

  if (norm.includes('cisco_nxos') || norm.includes('nxos')) {
    return `hostname ${hostname}\nfeature telnet\nfeature bash-shell\nusername admin password 0 PlainTextNexus123\nline vty\n exec-timeout 0`;
  }

  if (norm.includes('cisco') || norm.includes('ios')) {
    return `hostname ${hostname}\nno service password-encryption\nip http server\nusername admin privilege 15 password 0 PlainTextPassword123\nline vty 0 4\n transport input telnet ssh\n exec-timeout 0 0`;
  }

  if (norm.includes('juniper') || norm.includes('junos')) {
    return `system {\n    host-name ${hostname};\n    services {\n        telnet;\n        web-management {\n            http;\n        }\n    }\n}`;
  }

  if (norm.includes('paloalto') || norm.includes('panos')) {
    return `set deviceconfig system hostname ${hostname}\nset deviceconfig system service disable-telnet no\nset deviceconfig system service disable-http no`;
  }

  if (norm.includes('fortinet') || norm.includes('forti')) {
    return `config system global\n    set hostname "${hostname}"\n    set admintimeout 0\nend\nconfig system interface\n    edit "port1"\n        set allowaccess ping https ssh http telnet\n    next\nend`;
  }

  return `hostname ${hostname}\n! Telemetry snapshot for ${hostname} (${vendorType})\nservice password-encryption disabled\ntelnet server enable\nusername admin password admin123`;
}

/**
 * Generates vendor-specific "show version" CLI outputs
 */
export function generateVendorVersion(hostname: string, vendorType: string): string {
  const norm = (vendorType || '').toLowerCase().replace(/[^a-z0-9_]/g, '');

  // Aruba / HPE (ArubaOS-CX)
  if (norm.includes('aruba') || norm.includes('aoscx')) {
    return `ArubaOS-CX 10.12.1000
Header: ArubaOS-CX 10.12.1000 (FL.10.12.1000)
Built: 2024-03-15 14:22:10 UTC
Hardware: JL640A (Aruba 8360-32Y4C Switch)
Serial Number: SG12345678
System Uptime: 142 days, 8 hours, 15 minutes`;
  }

  // Huawei (VRP / CloudEngine)
  if (norm.includes('huawei') || norm.includes('vrp')) {
    return `Huawei Versatile Routing Platform Software
VRP (R) software, Version 8.180 (CE6881-48S6CQ V200R019C10SPC800)
Copyright (C) 2012-2023 Huawei Technologies Co., Ltd.
HUAWEI CE6881-48S6CQ uptime is 98 days, 14 hours, 43 minutes
System SERIAL NUMBER: 2102352BQS10M3000012`;
  }

  // Dell Technologies (Dell OS10)
  if (norm.includes('dell') || norm.includes('os10')) {
    return `Dell SmartFabric OS10 Enterprise
OS Version: 10.5.5.4P1
Build Version: 10.5.5.4P1.129
Hardware: S5248F-ON (48x25GbE SFP28 + 6x100GbE QSFP28)
System Serial: 99ABC12
System Uptime: 65 days 04:12:00`;
  }

  if (norm.includes('arista') || norm.includes('eos')) {
    return `Arista EOS Software Version 4.28.2F
Architecture: i686
Internal build version: 4.28.2F-28038781.4282F
Hardware MAC address: 001c.73a1.4b01
System MAC address: 001c.73a1.4b01
Serial number: JPE18210042
Uptime: 42 days, 11 hours, 22 minutes`;
  }

  if (norm.includes('cisco_nxos') || norm.includes('nxos')) {
    return `Cisco Nexus Operating System (NX-OS) Software
Software BIOS: version 07.69
NXOS: version 9.3(8)
cisco N9K-C93180YC-EX
Uptime is 104 day(s), 6 hour(s), 14 minute(s)`;
  }

  if (norm.includes('cisco') || norm.includes('ios')) {
    return `Cisco IOS Software, C3560CX Software (C3560CX-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2021 by Cisco Systems, Inc.
System image file is "flash:c3560cx-universalk9-mz.152-7.E4.bin"
Uptime is 87 days, 4 hours, 10 minutes`;
  }

  if (norm.includes('juniper') || norm.includes('junos')) {
    return `Hostname: ${hostname}
Model: mx240
Junos: 21.4R1.12
JUNOS OS Kernel 64-bit [21.4R1.12]
JUNOS Base OS Software Suite [21.4R1.12]`;
  }

  if (norm.includes('paloalto') || norm.includes('panos')) {
    return `PA-3220
sw-version: 10.1.6
global-protect-client-version: 5.2.10
app-version: 8540-7312
threat-version: 8540-7312
uptime: 210 days, 12 hrs, 05 mins`;
  }

  if (norm.includes('fortinet') || norm.includes('forti')) {
    return `FortiGate-VM64 v7.2.4,build1396,230309 (GA.F)
Virus-DB: 1.00000(2023-01-01 00:00)
Extended DB: 1.00000(2023-01-01 00:00)
IPS-DB: 6.00741(2021-12-01 02:30)`;
  }

  return `${hostname} Enterprise OS Version 12.4(3) LTS
Architecture: x86_64
System Serial: SN-A1948201938
Uptime: 12 days, 4 hours`;
}