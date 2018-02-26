**VirusTotal Results for IP Lookup**

{{ verbose_msg }}
{% for resolution in resolutions %}
    Resolved as: {{ resolution.hostname }} on {{ resolution.last_resolved }}
{% endfor %}

Last Scanned: {{ scan_date }}
Positives: {{ positives }}/{{ total }}

{% if error %}
{{ error }}
{% endif %}