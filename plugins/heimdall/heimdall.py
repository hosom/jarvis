import requests
import json

from errbot import BotPlugin, arg_botcmd

class Heimdall(BotPlugin):
	'''
	Heimdall blocklisting.
	'''

	def get_configuration_template(self):
		return dict(
				token='xx',
				host='http://127.0.0.1:5000'
			)

	@arg_botcmd('blocklist', type=str, template='blocklist')
	def heimdall_blocklist(self, message, blocklist=None):
		'''
		Retrive a particular blocklist.
		'''
		if not self.config:
			return dict(error='Not yet configured.')

		resp = requests.get('{0}/{1}'.format(self.config.get('host'), blocklist))
		results = [line.strip() for line in resp.text.split('\n')]

		return dict(results=results)

	@arg_botcmd('ip', type=str, template='block')
	@arg_botcmd('reason', type=str)
	@arg_botcmd('--mask', type=str, default=None)
	@arg_botcmd('--tags', type=str, default=None)
	def heimdall_block_ip(self, message, ip=None, reason=None, mask=None, tags=None):
		'''
		Block an IP address using Heimdall.
		'''
		if not self.config:
			return dict(error='Not yet configured.')

		headers = {'x-api-key': self.config.get('token')}

		if not mask:
			mask = ''
		else:
			mask = '/{0}'.format(mask)

		data = dict(reason=reason, tags=tags.split(','))

		resp = requests.post('{0}/block/ip/{1}{2}'.format(self.config.get('host'), ip, mask), 
							headers=headers,
							data=json.dumps(data))

		results = resp.text

		return dict(results=results)

	@arg_botcmd('host', type=str, template='block')
	@arg_botcmd('reason', type=str)
	@arg_botcmd('--tags', type=str, default=None)
	def heimdall_block_host(self, message, host=None, reason=None, tags=None):
		'''
		Block a hostname using Heimdall.
		'''
		if not self.config:
			return dict(error='Not yet configured')

		headers = {'x-api-key': self.config.get('token')}

		data = dict(reason=reason, tags=tags.split(','))

		resp = requests.post('{0}/block/host/{1}'.format(self.config.get('host'), host),
							headers=headers,
							data=json.dumps(data))

		results = resp.text

		return dict(results=results)