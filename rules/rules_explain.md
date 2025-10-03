Breaking it down

alert

Tells Suricata what to do when it sees traffic that matches the rule.

Here, it will generate an alert.

Other options exist like drop or reject, but those are usually for IPS. For NIDS, we just use alert.

http

The protocol the rule looks at.

Suricata supports many protocols: http, dns, tls, ftp, tcp, udp, etc.

This rule only looks at HTTP traffic.

any any -> any any

Defines source IP & port → destination IP & port.

any any means any IP, any port. The rule will match all HTTP traffic.

You can make it more specific (e.g., a specific web server or local network IP).

( ... )

Everything inside the parentheses are options/settings for the rule:

msg:"DEMO HTTP EvilTest string detected"

The message that appears in alerts/logs when triggered.

content:"eviltest"

What Suricata looks for inside the HTTP request.

If it finds "eviltest", the alert triggers.

sid:1000001

A unique ID for this rule. Each rule must have a different SID.

rev:1

Revision number. Increment if you update the rule later.

classtype:trojan

The type of attack. Optional, but helps categorize alerts for analysis.
