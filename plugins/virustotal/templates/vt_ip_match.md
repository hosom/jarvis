{% for result in results %}
[VirusTotal IP Address Report for {{ result.ip }}]({{ result.permalink }})
{% endfor %}