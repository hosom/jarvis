{% if err %}
{{ indicator_document }}
{{ err }}
{% else %}
Added {{ indicator }} to miner {{ miner }}.
{% endif %}