import random
import hashlib
import base64
import requests
import jwt
import time
import sys
import logging

VJWT_TTL_SECONDS = 300.0


class AuditClient:
    def __init__(self, apiTokenSecret, apiTokenId, apiHost, apiPath):
        self.apiTokenSecret = apiTokenSecret
        self.apiTokenId = apiTokenId
        self.apiHost = apiHost
        self.apiPath = apiPath

    def fetchRecords(self, req):
        vjwtString = self.__generateVjwtString(req)

        headers = {
            'Authorization': 'VJWTv1.0.0 ' + vjwtString.decode()
        }

        apiUrl = self.apiHost + self.apiPath
        try:
            response = requests.get("https://" + apiUrl,
                                    params=req['query'], headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.error(
                'An Error occured while trying to fetch records, verify the information in your config.ini')
            sys.exit(1)

        return response.json()

    def __generateVjwtString(self, req):
        tokenSecret = base64.b64decode(self.apiTokenSecret)
        queryKeys = req['query'].keys()
        method = req['method']

        queryParams = self.__generateQueryParams(req['query'], queryKeys)
        nonce = self.__generateNonce()

        payload = {
            'sub': self.apiTokenId,
            'iat': int(time.time()),
            'jti': nonce,
            'rsha': self.__generateRsha(method, self.apiHost, self.apiPath, queryParams),
            'rqps': ','.join(queryKeys),
            'exp': int(time.time()+VJWT_TTL_SECONDS)
        }
        return jwt.encode(payload, tokenSecret, algorithm='HS256')

    def __generateQueryParams(self, query, keys):
        result = ''
        for key in keys:
            result = result+'%s=%s' % (key, query[key])

            # for key, value in query.items():
            #     result = result+"%s=%s" % (key, value)
        return result

    def __generateNonce(self, length=8):
        return ''.join([str(random.randint(0, 9)) for i in range(length)])

    def __generateRsha(self, method, host, path, queryParams):
        hash = hashlib.sha256(
            (method + host + path + queryParams).encode('utf-8')).digest()
        b64Hash = base64.urlsafe_b64encode(hash)

        # Remove padding
        b64Hash = b64Hash.decode().replace('=', '')
        return b64Hash
