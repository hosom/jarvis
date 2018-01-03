{% if chat_enrollment %}
{{ user }} has been enrolled via chat.

To mitigate the security concerns of sharing secrets via chat, instruct {{ user }} to remove references to the secret from their chat.
{% else %}
A token for {{ user }} has been created and stored in the Bot **data** directory configured within your **config.py**. This token QRCode should be shared with {{ user }} out of band to avoid compromise of this secret.

{% endif %}