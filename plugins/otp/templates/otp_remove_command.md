{{ command }} has been removed from the list of OTP filtered commands.
{% if err %}
{{ command }} is not an OTP filtered command. Ignoring.
{% endif %}