import re
import ipaddress
import requests

from errbot import BotPlugin, re_botcmd

# VirusTotal API Base URL
_VTAPI = 'https://www.virustotal.com/vtapi/v2/file/report'
# Base URL for creating links to VirusTotal File reports
_ALT_FILE_URL = 'https://www.virustotal.com/#/file/'
# Base URL for creating links to VirusTotal IP reports
_ALT_IP_URL = 'https://www.virustotal.com/#/ip-address/'

class VirusTotal(BotPlugin):
	'''Perform lookups against VirusTotal API if an API key has been set.
	
	Without an API key, this plugin will provide direct links to
	VirusTotal reports.
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
		'''configure is used to override configuration to populate _private_nets.

		_private_nets can then be used to filter for networks that should not be 
		looked up automatically.
		'''
		if configuration is not None and configuration != {}:
			config = configuration
		else:
			config = self.get_configuration_template()

		private_nets = [ipaddress.IPv4Network(addr) for addr in config['private_nets']]
		self._private_nets = private_nets

		super(VirusTotal, self).configure(config)

	# Match sha256,sha1,md5
	@re_botcmd(pattern=r'([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})', 
		matchall=True, prefixed=False, flags=re.IGNORECASE, 
		template='hash_lookup')
	def vt_hash_lookup(self, message, matches):
		'''vt_hash_lookup matches against hashes in chat and then performs lookups
		against the VirusTotal API. 

		If an API key is unavailable, the bot will reply with a link to the file
		report on VirusTotal.
		'''
		vt_results = []
		for match in matches:
			if len(matches) > 15:
				return dict(err='Too many hashes to lookup in one batch.')
			file_hash = match.group(0)
			
			# Perform an actual lookup if we have an API key
			if self.config.get('vt_apikey') != 'VirusTotal API key':
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

	# Match IPv4
	@re_botcmd(pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
		matchall=True, prefixed=False, flags=re.IGNORECASE,
		template='ip_lookup')
	def vt_ip_lookup(self, message, matches):
		'''vt_ip_lookup matches against IP addresses in chat and performs lookups
		against the VirusTotal API. 

		If an API key is unavailable, the bot will reply with a link to the IP 
		report in VirusTotal.
		'''

		vt_results = []

		for match in matches:
			if len(matches) > 15:
				return dict(err='Too many IP addresses to lookup in one batch.')
			ipaddr = match.group(0)

			if self.config.get('vt_apikey') != 'VirusTotal API key':
				params = dict(
					apikey=self.config.get('vt_apikey'),
					resource=ipaddr
				)
				r = requests.post(_VTAPI)
				vt_result = r.json()
				vt_result['api_enabled'] = True
				vt_result['ipaddr'] = ipaddr
				vt_result['url'] = vt_result['permalink']
				vt_results.append(vt_result)
			else:
				vt_results.append(
					dict(url='{0}{1}'.format(_ALT_IP_URL, ipaddr), 
						ipaddr=ipaddr))
						
		return dict(vt_results=vt_results)