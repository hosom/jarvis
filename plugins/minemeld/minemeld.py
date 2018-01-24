import requests

from errbot impvort BotPlugin, arg_botcmd

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

    @arg_botcmd('miner', type=str, template='add')
    @arg_botcmd('indicator', type=str)
    @arg_botcmd('indicator_type', type=str)
    @arg_botcmd('comment', type=str)
    @arg_botcmd('--share-level', type=str, default='green')
    def minemeld_add(self, message, miner=miner, indicator=indicator, indicator_type=indicator_type, comment=comment, share_level=share_level):
        '''Add an indicator to a specified Minemeld list.
        '''

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
                                auth=(self.config.get('username'), self.config.get('password')),
                                verify=self.config.get('ssl_verify'))
            
            if r.status_code != requests.codes.ok:
                return dict(err='Request to server failed with error code {0}'.format(r.status_code))

        else:
            return dict(err='This plugin cannot be used without configuration.')
        
        return dict(indicator=indicator, miner=miner)