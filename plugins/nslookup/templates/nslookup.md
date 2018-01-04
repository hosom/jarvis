**DNS Resolution for: {{ name }}**
{% if err %}
{{ err }}
{% else %}
{% for answer in answers %}
{{ answer }}
{% endfor %}
{% endif %}