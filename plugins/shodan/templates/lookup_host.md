[**Shodan Host Report for {{ ip_str }}**]({{ permalink }})

**Seen Names:** {% for hostname in hostnames %}{{ hostname }} {% endfor %}

**Vulns:** {% for vuln in vulns %}{{ vuln }} {% endfor %}

**Ports:** {% for port in ports %}{{ port }} {% endfor %}

**Location:** {{ city }}, {{ country_name }}

**AS Data:** Org: {{ org }}, ISP: {{ isp }}, ASN: {{ asn }}

**Tags:** {% for tag in tags %}{{ tag }} {% endfor %}

**Last Update:** {{ last_update }}