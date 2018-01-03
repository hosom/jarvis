{% for result in ip_results %}
**IP Lookup Results for {{ result.ip }}**
{% if err %}
{{ err }}
{% else %}
**Registrant**: {{ result.asn_answer.registrant }}, **Registry Date**: {{ result.asn_answer.registry_date }}

**Subnet**: {{ result.origin_answer.subnet }}

**ASN**: {{ result.origin_answer.asn }}, **Country**: {{ result.origin_answer.country }}, **Issuer**: {{ result.origin_answer.issuer }}
{% endif %}
{% endfor %}