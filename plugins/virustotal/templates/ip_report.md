**VirusTotal Results for IP Lookup**

{{ verbose_msg }}
{% for resolution in resolutions %}
    Resolved as: {{ resolution.hostname }} on {{ resolution.last_resolved }}
{% endfor %}

{% if error %}
{{ error }}
{% endif %}