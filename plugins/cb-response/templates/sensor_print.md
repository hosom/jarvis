[**{{ sensor.hostname }}**]({{ sensor.webui_link }}) ({{ sensor.status }})
Operating System: {{ sensor.os }}
{% for interface in sensor.network_interfaces %}
Network Interface: {{ interface.ipaddr }}, {{ interface.macaddr }}
{% endfor %}
Isolation Status: {{ sensor.is_isolating }}
Last Checkin: {{ sensor.last_checkin_time }}