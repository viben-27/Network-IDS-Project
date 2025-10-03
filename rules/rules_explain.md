alert

This tells Suricata what to do when it sees traffic that matches the rule.

Here, it will generate an alert.

Other options exist like drop or reject, but those are usually for IPS (Intrusion Prevention System). For NIDS, we just alert.

http

This is the type of traffic the rule looks at.

Suricata can check lots of traffic types: http, dns, tls, ftp, tcp, udp, etc.

Here, it only looks at HTTP traffic.

any any -> any any

This shows the source and destination: source IP + port -> destination IP + port.

any any means any IP, any port. So this rule will match all HTTP traffic.

You can make it more specific, like your network IP or a particular server port, if you want.

( ... )

Everything inside the parentheses are extra options or settings for the rule.

msg:"DEMO HTTP EvilTest string detected"

The message that will show up when an alert triggers.

content:"eviltest"

Suricata looks inside the HTTP request for the word "eviltest".

If it sees it, it triggers the alert.

sid:1000001

A unique ID for this rule. Each rule must have a different SID.

rev:1

The revision number. If you update the rule later, you can increase this number.

classtype:trojan

This is the type of attack. Optional, but helps categorize alerts for easier analysis.
