import re
import requests

from errbot import BotPlugin, re_botcmd

_VTAPI = 'https://www.virustotal.com/vtapi/v2/file/report'
_ALT_FILE_URL = 'https://www.virustotal.com/#/file/'

_ALT_IP_URL = 'https://www.virustotal.com/#/ip-address/'

class VirusTotal(BotPlugin):
	'''
	VirusTotal lookups.
	'''

	def get_configuration_template(self):
		return dict(
				vt_apikey='VirusTotal API key',
				private_nets=['0.0.0.0/8',
							'10.0.0.0/8',
							'127.0.0.0/8',
							'169.254.0.0/16',
							'172.16.0.0/12',
							'192.168.0.0/16',
							'255.255.255.255/32']				
			)

	def configure(self, configuration):
		'''
		Override configuration to make sure that _private_nets is generated
		and can be used to ignore certain networks.
		'''
		if configuration is not None and configuration != {}:
			config = configuration
		else:
			config = self.get_configuration_template()

		private_nets = [ipaddress.IPv4Network(addr) for addr in config['private_nets']]
		self._private_nets = private_nets

		super(VirusTotal, self).configure(config)

	@re_botcmd(pattern=r'([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})', 
		matchall=True, prefixed=False, flags=re.IGNORECASE, 
		template='hash_lookup')
	def hashmatch(self, message, matches):
		'''
		Match against and lookup a hash anywhere in chat on VirusTotal
		'''
		vt_results = []
		for match in matches:
			if len(matches) > 15:
				return dict(err='Too many hashes to lookup in one batch.')
			file_hash = match.group(0)
			
			# Perform an actual lookup if we have an API key
			if self.config.get('vt_apikey') is not 'VirusTotal API key':
				params = dict(
					apikey=self.config.get('vt_apikey'),
					resource=file_hash
					)
				r = requests.post(_VTAPI, data=params)
				vt_result = r.json()
				vt_result['api_enabled'] = True
				vt_result['file_hash'] = file_hash
				vt_result['url'] = vt_result['permalink']
				vt_results.append(vt_result)
			else:
				vt_results.append(
					dict(url='{0}{1}'.format(_ALT_FILE_URL, file_hash),
						file_hash=file_hash))
		
		return dict(vt_results=vt_results)

	@re_botcmd(pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
				matchall=True, prefixed=False, flags=re.IGNORECASE,
				template='ip_lookup')
	def ipmatch(self, message, matches):
		'''
		Match against and lookup IP addresses anywhere in chat on VirusTotal
		'''

		vt_results = []

		for match in matches:
			if len(matches) > 15:
				return dict(err='Too many IP addresses to lookup in one batch.')
			
			ipaddr = match.group(0)
			vt_results.append(dict(url='{0}{1}'.format(_ALT_IP_URL, ipaddr), 
					ipaddr=ipaddr))
		return dict(vt_results=vt_results)