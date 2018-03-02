import re
import ipaddress
import requests
import json

from errbot import BotPlugin, arg_botcmd, re_botcmd

# VirusTotal API Base URL
_VT_BASE = 'https://www.virustotal.com/vtapi/v2/'
# Base URL for creating links to VirusTotal File reports
_ALT_FILE_URL = 'https://www.virustotal.com/#/file/'
# Base URL for creating links to VirusTotal IP reports
_ALT_IP_URL = 'https://www.virustotal.com/#/ip-address/'

class VirusTotal(BotPlugin):
	'''Perform lookups against VirusTotal API.
	'''

	def get_configuration_template(self):
		return dict(
				vt_apikey='VirusTotal API key',	
			)

	@arg_botcmd('hash', type=str, template='file_report',
				help='Hash to lookup a file with.')
	def vt_file_lookup(self, message, hash=None):
		'''Retrieve the VirusTotal report for a file with its hash.
		'''

		self.log.info('Performing lookup of hash {0} in VirusTotal'.format(hash))
		url = '{0}{1}'.format(_VT_BASE, 'file/report')
		params = dict(apikey=self.config.get('vt_apikey'), 
						resource=hash)
		response = requests.get(url, params=params)
		self.log.info('Received response of {0} from VirusTotal.'.format(response.status_code))
		try:
			report = response.json()
		except json.decoder.JSONDecodeError:
			self.log.info('Error processing, message received: {0}'.format(response.text))
			return dict(error=response.text)
		return report

	@arg_botcmd('ip', type=str, template='ip_report',
				help='IP address to lookup.')
	def vt_ip_lookup(self, message, ip=None):
		'''Retrieve the VirusTotal report for an IP address.
		'''

		self.log.info('Performing lookup of ip {0} in VirusTotal'.format(ip))
		url = '{0}{1}'.format(_VT_BASE, 'ip-address/report')
		params = dict(apikey=self.config.get('vt_apikey'), 
					ip=ip)
		response = requests.get(url, params=params)
		self.log.info('Received response of {0} from VirusTotal.'.format(response.status_code))
		try:
			report = response.json()
		except json.decoder.JSONDecodeError:
			self.log.info('Error processing, message received: {0}'.format(response.text))
			return dict(error=response.text)
		report['permalink'] = '{0}{1}'.format(_ALT_IP_URL, ip)
		return report

	@re_botcmd(pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
	matchall=True, prefixed=False, flags=re.IGNORECASE, template='ip_match')
	def vt_ip_match(self, message, matches):
		'''Automatic IP address lookups.
		'''

		results = []
		for match in matches:
			ip = match.group(0)
			results.append(dict(permalink='{0}{1}'.format(_ALT_IP_URL, ip), ip=ip))
		
		return dict(results=results)

	@re_botcmd(pattern=r'([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})', 
		matchall=True, prefixed=False, flags=re.IGNORECASE, 
		template='hash_match')
	def vt_hash_match(self, message, matches):
		'''Automatic hash lookups.
		'''

		results = []
		for match in matches:
			checksum = match.group(0)
			results.append(dict(permalink='{0}{1}'.format(_ALT_FILE_URL, checksum), hash=checksum))
		
		return dict(results=results)