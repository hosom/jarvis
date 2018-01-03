import re
import requests

from errbot import BotPlugin, re_botcmd

_VTAPI = 'https://www.virustotal.com/vtapi/v2/file/report'
_ALT_URL = 'https://www.virustotal.com/#/file/'

class CbResponse(BotPlugin):
	'''
	VirusTotal lookups.
	'''

	def get_configuration_template(self):
		return dict(
				vt_apikey='VirusTotal API key'
			)

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
			if self.config:
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
					dict(url='{0}{1}'.format(_ALT_URL, file_hash),
						file_hash=file_hash))
		
		return dict(vt_results=vt_results)

'''
	@re_botcmd(pattern=r'', matchall=True, prefixed=False, flags=re.IGNORECASE,
		template='ip_lookup')
	def ipmatch(self, message, matches):
'''