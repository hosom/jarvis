{% for result in results %}
[VirusTotal File Report for {{ result.hash }}]({{ result.permalink }})
{% endfor %}