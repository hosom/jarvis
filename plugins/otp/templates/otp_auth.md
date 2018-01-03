{% if group_chat %}
OTP authentication cannot be performed within a group chat channel.
{% endif %}

{% if not_enrolled %}
You are not enrolled in OTP.
Please contact a Bot Administrator to enroll.
{% endif %}

{% if success %}
OTP Authentication successful.
{% else %}
OTP Authentication failed.
After 10 failed attempts, your token will be destroyed and will need to be reset by a Bot Administrator.
{% endif %}