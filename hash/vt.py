import requests
import json
import re
from time import sleep


class VT:
    def __init__(self, apikey):
        self.baseurl = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }

    def get_hash(self, hash):
        malicious_search = re.compile(r'malicious', flags=re.IGNORECASE)
        self.response = requests.get(f'{self.baseurl}search?query={hash}', headers=self.headers)
        self.answer = json.loads(self.response.text)
        try:
            self.data = self.answer['data'][0]
            type_description = self.data['attributes']['type_description']
            reputation = self.data['attributes']['reputation']
            threat_label = self.data['attributes']['popular_threat_classification']['suggested_threat_label']
            total_votes_list = []
            results_list = []
            for k, v in self.data['attributes']['total_votes'].items():
                total_votes_list.append(f'{k}: {v}')					
            for result in self.data['attributes']['last_analysis_results'].items():
                av_name = result[1]['engine_name']
                av_category = result[1]['category']
                results_list.append(f'{av_name}: {av_category}')
            malicious_list = []
            for result in results_list:
                if malicious_search.search(result):
                    malicious_list.append(result)
            threat_names = []
            for name in self.data['attributes']['popular_threat_classification']['popular_threat_name']:
                threat_name = name['value']
                threat_names.append(threat_name)
            threat_names = ', '.join(threat_names)
            total_votes_data = '\n'.join(total_votes_list)
            malicious_list.sort()
            results_data = '\n'.join(malicious_list)
            total_malicious = len(malicious_list)
            report = f'File Hash: {hash}\n\nType: {type_description}\nThreat Names: {threat_names}\nThreat Label: {threat_label}\nReputation: {reputation}\n\nTotal Votes:\n{total_votes_data}\n\n{total_malicious} Vendors identified this hash as malicious:\n{results_data}\n\n'
            return report
        except KeyError:
            error_message = self.answer['error']['message']
            error_cred = self.answer['error']['code']
            return f'No Virus Total data returned for {hash}\n\nError message: {error_message}\nError Type:  {error_cred}\n\nRe-enter your personal VT key'
        except Exception:
            return f'No Virus Total data available for {hash}'
