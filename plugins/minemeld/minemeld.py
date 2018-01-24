import requests

from errbot import BotPlugin, arg_botcmd

class Minemeld(BotPlugin):
    '''Interract with a Minemeld server to manage lists.
    '''

    def get_configuration_template(self):
        return dict(
            server="https://127.0.0.1",
            username="admin",
            password="minemeld",
            ssl_verify=True
        )

    @arg_botcmd('comment', type=str, template='add', help='Why the block is being added.')
    @arg_botcmd('indicator_type', type=str, template='add', help='The type of indicator to be added. IPv4, IPv6, domain, url')
    @arg_botcmd('indicator', type=str, template='add', help='The indicator to be added to the miner.')
    @arg_botcmd('miner', type=str, template='add', help='The minemeld miner to add the IP address to.')
    @arg_botcmd('--share-level', type=str, default='green', template='add', help='RED or GREEN')
    def minemeld_add(self, message, miner=None, indicator=None, indicator_type=None, comment=None, share_level=None):
        '''Add an indicator to a specified Minemeld list.

        Example: 

        minemeld add blInboundIPv4 8.8.8.8 IPv4 "Google DNS"
        '''
        if not miner or not indicator or not indicator_type or not comment:
                return dict(err='This command requires all positional arguments.')
        if self.config:
            indicator_document = dict(
                indicator=indicator, 
                share_level=share_level,
                type=indicator_type,
                comment=comment
            )

            url = self.config.get('server')
            r = requests.post('{0}/config/data/{1}_indicators/append?h={2}'.format(url, miner, miner),
                                json=indicator_document,
                                headers={'Content-Type': 'application/json'},
                                auth=(self.config.get('username'), self.config.get('password')),
                                verify=self.config.get('ssl_verify'))
            
            if r.status_code != requests.codes.ok:
                return dict(indicator_document=indicator_document, err='Request to server failed with error code {0}'.format(r.status_code))

        else:
            return dict(indicator_document=indicator_document, err='This plugin cannot be used without configuration.')
        
        return dict(indicator=indicator, miner=miner)