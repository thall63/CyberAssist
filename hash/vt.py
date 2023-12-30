import requests
import json
from time import sleep


class VT:
    def __init__(self, apikey):
        self.baseurl = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }


    def get_hash(self, hash):
        self.response = requests.get(f'{self.baseurl}search?query={hash}', headers=self.headers)
        self.answer = json.loads(self.response.text)
        try:
            self.data = self.answer['data'][0]
            type_description = self.data['attributes']['type_description']
            reputation = self.data['attributes']['reputation']
            total_votes_list = []
            results_list = []
            for k, v in self.data['attributes']['total_votes'].items():
                total_votes_list.append(f'{k}: {v}')					
            for result in self.data['attributes']['last_analysis_results'].items():
                av_name = result[1]['engine_name']
                av_category = result[1]['category']
                results_list.append(f'{av_name}: {av_category}')
            total_votes_data = '\n'.join(total_votes_list)
            results_data = '\n'.join(results_list)
            report = f'File Hash: {hash}\n\nType: {type_description}\nReputation: {reputation}\n\nTotal Votes:\n{total_votes_data}\n\nResults:\n{results_data}'
            return report
        except Exception as e:
            return f'No data returned for {hash}:: {e}'
