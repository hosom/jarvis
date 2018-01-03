{% if sensors|length < 15 %}
{% for sensor in sensors %}
{{ sensor.hostname }} ({{ sensor.id }})
{% endfor %}
{% else %}
Sensor searched returned too many sensors.
Please refine your search and try again.
{% endif %}

{% if err %}
An error was encountered while performing your search.
Please check your syntax and try again.
{% endif %}