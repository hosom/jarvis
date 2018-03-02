import ipaddress

from errbot import BotPlugin

class LocalNets(BotPlugin):
    '''Central configuration for Local Networks.
    '''
    def get_configuration_template(self):
        return dict(local_nets=['0.0.0.0/8',
            '10.0.0.0/8',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '255.255.255.255/32'])

    def configure(self, configuration):
        '''
        Override configuration to make sure that local_nets is generated
        and can be used to ignore certain networks.
        '''
        if configuration is not None and configuration != {}:
            config = configuration
        else:
            config = self.get_configuration_template()

        local_nets = [ipaddress.IPv4Network(addr) for addr in config['local_nets']]
        self.local_nets = local_nets

        super(LocalNets, self).configure(config)