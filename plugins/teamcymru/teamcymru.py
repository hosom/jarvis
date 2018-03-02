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
	
	@re_botcmd(pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', hidden=True,
				matchall=True, prefixed=False, flags=re.IGNORECASE,
				template='tc_ip_match')
	def tc_ip_match(self, message, matches):
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
			for network in self.get_plugin('LocalNets').local_nets:
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