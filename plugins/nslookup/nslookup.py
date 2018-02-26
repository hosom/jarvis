import dns.resolver
import dns.reversename
import re

from errbot import BotPlugin, arg_botcmd

class Nslookup(BotPlugin):
	'''Perform name resolution of hostnames and IP addresses.
	'''

	ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)'
	ip_matcher = re.compile(ip_pattern)

	@arg_botcmd('name', type=str, template='nslookup')
	def nslookup(self, message, name=None):
		'''
		Perform a local dns lookup of a hostname or IP address.
		'''

		qtype = 'A'
		err = None

		# if this is an ip, do a reverse lookup instead
		if self.ip_matcher.match(name):
			name = dns.reversename.from_address(name)
			qtype = 'PTR'

		try:
			answers = dns.resolver.query(name, qtype)
		except dns.resolver.NXDOMAIN:
			answers = [None]
			err = 'DNS name not found.'
		except:
			answers = [None]
			err = 'Failed to resolve name.'


		return dict(name=name, answers=[str(answer) for answer in answers], err=err)