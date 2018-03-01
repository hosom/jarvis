import re
import ipaddress
import dns.resolver

from collections import namedtuple
from errbot import BotPlugin, re_botcmd

_IP_API = 'origin.asn.cymru.com'
_ASN_API = 'asn.cymru.com'

OriginReply = namedtuple('OriginReply', 'asn subnet country issuer registry_date')
ASReply = namedtuple('ASReply', 'asn country issuer registry_date registrant')

def get_fields(answers):
	answer = answers[0].to_text().strip('"')
	fields = answer.split(' |')
	return [field.strip() for field in fields]

class TeamCymru(BotPlugin):
	'''Perform lookups to the TeamCymru DNS APIs.
	'''

	def get_configuration_template(self):
		return dict(
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

		super(TeamCymru, self).configure(config)

	@re_botcmd(pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
				matchall=True, prefixed=False, flags=re.IGNORECASE,
				template='ip_lookup')
	def tc_ip_lookup(self, message, matches):
		'''
		Match against and lookup IP Addresses in TeamCymru's DNS API.
		'''

		ip_results = []
		for match in matches:
			try:
				ip = ipaddress.ip_address(match.group(0))
			except ValueError:
				continue

			ignore = False
			for network in self._private_nets:
				# check for ignored networks.
				if ip in network:
					ignore = True
					break

			if ignore:
				continue

			reverse_ip = '.'.join(reversed(str(ip).split('.')))
			err = None
			try:
				answers = dns.resolver.query('{0}.{1}'.format(reverse_ip, _IP_API), 'TXT')
			except dns.resolver.NXDOMAIN:
				err = 'Invalid IP or IP not found.'

			try:
				origin_answer = OriginReply(*get_fields(answers))
			except UnboundLocalError:
				origin_answer = None

			if not err:
				try:
					answers = dns.resolver.query('AS{0}.{1}'.format(origin_answer.asn, _ASN_API), 'TXT')
				except dns.resolver.NXDOMAIN:
					err = 'Error occurred on ASN lookup.'

			try:
				asn_answer = ASReply(*get_fields(answers))
			except UnboundLocalError:
				asn_answer = None

			# add the results to a list of dicts for the template
			ip_results.append(dict(
								ip=str(ip),
								origin_answer=origin_answer,
								asn_answer=asn_answer,
								err=err
							))

		return dict(ip_results=ip_results)