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
            # Need to parse data from answer and format for return
            return self.data
        except Exception as e:
            return f'No data returned for {hash}'
