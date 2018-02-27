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

"""
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
				self.log.info('VirusTotal API key configured, performing direct lookup.')
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
				self.log.info('VirusTotal API key is not configured. Returning link to report.')
				vt_results.append(
					dict(url='{0}{1}'.format(_ALT_FILE_URL, file_hash),
						file_hash=file_hash))
		
		return dict(vt_results=vt_results)
"""