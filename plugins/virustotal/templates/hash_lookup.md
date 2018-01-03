{% for result in vt_results %}
[**VirusTotal Results for {{ result.file_hash }}**]({{ result.url }})
{% if result.api_enabled %}
Scan Date: {{ result.scan_date }}
Score: {{ result.positives }} / {{ result.total }}
{% endif %}
{% endfor %}

{% if err %}
{{ err }}
{% endif %}