import os
import datetime
import hashlib
import hmac
import requests
 
# please don't store credentials directly in code
access_key = [access_ID]
secret_key = [access_KEY]
# request elements
http_method = 'GET'
host = 'storage.googleapis.com'
region = 'auto'
endpoint = 'https://storage.googleapis.com'
bucket = 'key-storage-mysql' # add a '/' before the bucket name to list buckets
object_key = 'test.txt'
request_parameters = ''
google_content_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
 
 
# hashing and signing methods
def hash(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
 
# region is a wildcard value that takes the place of the Gogole region value
# as COS doen't use the same conventions for regions, this parameter can accept any string
def createSignatureKey(key, datestamp, region, service):
 
    keyDate = hash(('GOOG4' + key).encode('utf-8'), datestamp)
    keyString = hash(keyDate, region)
    keyService = hash(keyString, service)
    keySigning = hash(keyService, 'goog4_request')
    return keySigning
 
 
# assemble the standardized request
time = datetime.datetime.utcnow()
timestamp = time.strftime('%Y%m%dT%H%M%SZ')
datestamp = time.strftime('%Y%m%d')
print('timestamp:' + timestamp)
print('datestamp:' + datestamp)
 
standardized_resource = '/' + bucket + '/' + object_key
standardized_querystring = request_parameters
standardized_headers = 'host:' + host + '\n' + 'x-goog-date:' + timestamp + '\n' 
signed_headers = 'host;x-goog-date'
payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()
 
standardized_request = (http_method + '\n' +
                        standardized_resource + '\n' +
                        standardized_querystring + '\n' +
                        standardized_headers + '\n' +
                        signed_headers + '\n' +
                        payload_hash).encode('utf-8')
 
 
# assemble string-to-sign
hashing_algorithm = 'GOOG4-HMAC-SHA256'
credential_scope = datestamp + '/' + region + '/' + 'storage' + '/' + 'goog4_request'
sts = (hashing_algorithm + '\n' +
       timestamp + '\n' +
       credential_scope + '\n' +
       hashlib.sha256(standardized_request).hexdigest())
 
 
# generate the signature
signature_key = createSignatureKey(secret_key, datestamp, region, 'storage')
signature = hmac.new(signature_key,
                     (sts).encode('utf-8'),
                     hashlib.sha256).hexdigest()
 
print ('=================================================\n')
print ('signature: ' + signature)
print ('=================================================\n')
 
 
# assemble all elements into the 'authorization' header
v4auth_header = (hashing_algorithm + ' ' +
                 'Credential=' + access_key + '/' + credential_scope + ', ' +
                 'SignedHeaders=' + signed_headers + ', ' +
                 'Signature=' + signature)
 
 
# create and send the request
headers = {'x-goog-date': timestamp, 'x-goog-content-sha256': google_content_sha256, 'Authorization': v4auth_header}
# the 'requests' package autmatically adds the required 'host' header
request_url = endpoint + standardized_resource + standardized_querystring
 
print('\nSending `%s` request to Google COS -----------------------' % http_method)
print('Request URL = ' + request_url)
request = requests.get(request_url, headers=headers)
 
print('\nResponse from Google COS ----------------------------------')
print('Response code: %d\n' % request.status_code)
print(request.text)
