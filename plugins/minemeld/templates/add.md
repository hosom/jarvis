{% if err %}
{{ indicator_document.indicator }}
{{ indicator_document.type }}
{{ indicator_document.share_level }}
{{ indicator_document.comment }}
{{ err }}
{% else %}
Added {{ indicator }} to miner {{ miner }}.
{% endif %}