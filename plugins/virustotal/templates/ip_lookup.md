{% for result in vt_results %}
[**VirusTotal Results for {{ result.ipaddr }}**]({{ result.url }})
{% if result.api_enabled %}
Scan Date: {{ result.scan_date }}
Score: {{ result.positives }} / {{ result.total }}
{% endif %}
{% endfor %}

{% if err %}
{{ err }}
{% endif %}