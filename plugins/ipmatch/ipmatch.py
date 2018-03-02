import re

from errbot import BotPlugin, re_botcmd

class IPMatch(BotPlugin):
    '''Perform actions whenever IP addresses are seen.
    '''

    @re_botcmd(pattern=r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    matchall=True, prefixed=False, flags=re.IGNORECASE,
    template='ip_match')
    def ip_match(self, message, matches):
        '''Automatic action whenever an IP address is seen.
        '''

        for match in matches:
            for response in self.get_plugin('VirusTotal').vt_ip_lookup(message, match.group(0)):
                self.log.info(response)
                self.send(message.frm, response)
        return dict(hello='Hello, World!')