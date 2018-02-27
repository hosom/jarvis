import shodan

from errbot import BotPlugin, arg_botcmd

# URL for Shodan Host permalinks
_HOST_URL = 'https://www.shodan.io/host/'

class Shodan(BotPlugin):
    '''Use the Shodan.io API.
    '''

    def get_configuration_template(self):
        return dict(
            apikey='Shodan API Key'
        )
    
    @arg_botcmd('ip', type=str, template='lookup_host',
        help='IP of the host to lookup.')
    def shodan_lookup_host(self, message, ip=None):
        '''Lookup an IP address in Shodan.
        '''
        api = shodan.Shodan(self.config.get('apikey'))
        host = api.host(ip)

        host['permalink'] = '{0}{1}'.format(_HOST_URL, ip)
        if not host.get('ip_str'):
            host['ip_str'] = ip

        return host