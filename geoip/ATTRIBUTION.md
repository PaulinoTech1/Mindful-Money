# GeoLite2 ASN Database Attribution

This product includes GeoLite2 data created by MaxMind, available from
https://www.maxmind.com.

The GeoLite2 ASN database is used for honeypot threat intelligence:
mapping attacker IP addresses to their Autonomous System Number (ASN)
and organization. This helps identify whether honeypot hits come from
VPS providers, VPN services, Tor exits, or residential ISPs.

License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)
https://creativecommons.org/licenses/by-sa/4.0/

Database file: GeoLite2-ASN.mmdb
Source: https://github.com/P3TERX/GeoLite.mmdb (community mirror of MaxMind data)
Last updated: 2026-10-12

The database is only queried when VAULT_IP_LOGGING=on. No data is sent to
MaxMind or any third party; all lookups are local file reads.
