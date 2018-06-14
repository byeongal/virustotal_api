import requests, json, os, time, sys

LIST_OF_HTTP_STATUS_CODES = {
    100 : "Continue", 101 : "Switching Protocols", 102 : "Processing", 103 : "Early Hints",
    200 : "OK", 201 : "Created", 202 : "Accepted", 203 : "Non-Authoritative Information", 204 : "No Content",
    205 : "Reset Content", 206 : "Partial Content", 207 : "Multi-Status", 208 : "Already Reported", 226 : "226 IM Used",
    300 : "Multiple Choices", 301 : "Moved Permanently", 302 : "Found", 303 : "See Other", 304 : "Not Modified",
    305 : "Use Proxy", 306 : "Switch Proxy", 307 : "Temporary Redirect", 308 : "Permanent Redirect",
    400 : "Bad Request", 401 : "Unauthorized", 402 : "Payment Required", 403 : "Forbidden", 404 : "Not Found",
    405 : "Method Not Allowed", 406 : "Not Acceptable", 407 : "Proxy Authentication Required", 408 : "Request Timeout", 409 : "Conflict",
    410 : "Gone", 411 : "Length Required", 412 : "Precondition Failed", 413 : "Payload Too Large", 414 : "URI Too Long",
    415 : "Unsupported Media Type", 416 : "Range Not Satisfiable", 417 : "Expectation Failed", 418 : "I'm a teapot", 421 : "Misdirected Request",
    422 : "Unprocessable Entity", 423 : "Locked", 424 : "Failed Dependency", 426 : "Upgrade Required", 428 : "Precondition Required",
    429 : "Too Many Requests", 431 : "Request Header Fields Too Large", 451 : "Unavailable For Legal Reasons",
    500 : "Internal Server Error", 501 : "Not Implemented", 502 : "Bad Gateway", 503 : "Service Unavailable", 504 : "Gateway Timeout",
    505 : "HTTP Version Not Supported", 506 : "Variant Also Negotiates", 507 : "Insufficient Storage", 508 : "Loop Detected",
    510 : "Not Extended", 511 : "Network Authentication Required",
}

INTERVAL_TIME = 0.05

class VirusTotalFile :
    def __init__(self, apikey) :
        self.__apikey = apikey

    # Public, Private
    def scan(self, file_path) :
        ret = False
        if os.path.getsize(file_path) >= 32000000:
            print('File size limit is 32MB')
            return ret
        try:
            params = {'apikey': self.__apikey}
            file_path = file_path.replace(os.sep, '/')
            with open(file_path, 'rb') as f:
                files = {'file': (file_path, f)}
                response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
                time.sleep(INTERVAL_TIME)
            if response.status_code == 200:
                response_json = response.json()
                response_code = response_json['response_code']
                if response_code == 1:
                    print(response_json['verbose_msg'])
                    ret = True
                else :
                    print('The event of some unexpected error')
            elif response.status_code == 204:
                print('Request rate limit exceeded. You are making more requests than allowed.')
            elif response.status_code == 400:
                print('Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
            elif response.status_code == 403:
                print('Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
            else:
                print("HTTP Request Error{} : {}".format(response.status_code, LIST_OF_HTTP_STATUS_CODES.get(response.status_code, 'Unknown')))
        except Exception as e:
            print(e)
        finally:
            time.sleep(INTERVAL_TIME)
            return ret

    # Private ( Not Tested )
    def scan_upload_url(self, file_path):
        ret = False
        if os.path.getsize(file_path) >= 32000000:
            print('File size limit is 32MB')
            return ret
        try:
            params = {'apikey': self.__apikey}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/scan/upload_url', params=params)
            time.sleep(INTERVAL_TIME)
            if response.status_code == 200:
                json_response = response.json()
                upload_url = json_response['upload_url']
                file_path = file_path.replace(os.sep, '/')
                with open(file_path, 'rb') as f:
                    files = {'file': (file_path.decode('utf-8'), open(file_path, 'rb'))}
                    response = requests.post(upload_url, files=files)
                    time.sleep(INTERVAL_TIME)
                    if response.status_code == 200:
                        pass
                    elif response.status_code == 204:
                        print('Request rate limit exceeded. You are making more requests than allowed.')
                    elif response.status_code == 400:
                        print(
                            'Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
                    elif response.status_code == 403:
                        print(
                            'Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
                    else:
                        print("HTTP Request Error{} : {}".format(response.status_code,
                                                                 LIST_OF_HTTP_STATUS_CODES.get(response.status_code,
                                                                                               'Unknown')))
            elif response.status_code == 204:
                print('Request rate limit exceeded. You are making more requests than allowed.')
            elif response.status_code == 400:
                print(
                    'Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
            elif response.status_code == 403:
                print(
                    'Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
            else:
                print("HTTP Request Error{} : {}".format(response.status_code,
                                                         LIST_OF_HTTP_STATUS_CODES.get(response.status_code,
                                                                                       'Unknown')))
            pass
        except Exception as e:
            print(e)
        finally:
            return ret

    # Public, Private
    def rescan(self, resource):
        ret = False
        params = {'apikey': self.__apikey, 'resource': resource}
        try:
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)
            time.sleep(INTERVAL_TIME)
            json_response = response.json()
            if response.status_code == 200:
                response_json = response.json()
                response_code = response_json['response_code']
                if response_code == 1:
                    print('The file corresponding to the given hash was successfully queued for rescanning.')
                    ret = True
                elif response_code == 0:
                    print('The file was not present in our file store.')
                else:
                    print('The event of some unexpected error')
            elif response.status_code == 204:
                print('Request rate limit exceeded. You are making more requests than allowed.')
            elif response.status_code == 400:
                print('Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
            elif response.status_code == 403:
                print('Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
            else:
                print("HTTP Request Error{} : {}".format(response.status_code,LIST_OF_HTTP_STATUS_CODES.get(response.status_code,'Unknown')))
        except Exception as e:
            print(e)
        finally:
            return ret

    # Private ( Not Tested )
    def rescan_delete(self, resource):
        ret = False
        params = {'apikey': self.__apikey, 'resource': resource}
        try :
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan/delete', params=params)
            time.sleep(INTERVAL_TIME)
            if response.status_code == 200:
                response_json = response.json()
                response_code = response_json['response_code']
                if response_code == 1:
                    print('The scheduled scan deletion succeed.')
                    ret = True
                elif response_code == -1 :
                    print('The scheduled scan deletion failed for whatever reason.')
            elif response.status_code == 204:
                print('Request rate limit exceeded. You are making more requests than allowed.')
            elif response.status_code == 400:
                print('Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
            elif response.status_code == 403:
                print('Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
            else:
                print("HTTP Request Error{} : {}".format(response.status_code,LIST_OF_HTTP_STATUS_CODES.get(response.status_code,'Unknown')))
        except Exception as e:
            print(e)
        finally:
            return ret

    # Public, Private
    def report(self, resource, dst_path):
        ret = False
        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': self.__apikey, 'resource': resource}
            response = requests.get(url, params=params)
            time.sleep(INTERVAL_TIME)
            if response.status_code == 200:
                response_json = response.json()
                response_code = response_json['response_code']
                if response_code == 1:
                    print(response_json['verbose_msg'])
                    with open(os.path.join(dst_path, resource + '.json'), 'w', encoding='utf8') as f:
                        json.dump(response_json, f, ensure_ascii=False, indent=4)
                    ret = True
                else :
                    print('The event of some unexpected error')
                    print(response_json['verbose_msg'])
            elif response.status_code == 204:
                print('Request rate limit exceeded. You are making more requests than allowed.')
            elif response.status_code == 400:
                print('Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
            elif response.status_code == 403:
                print('Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
            else:
                print("HTTP Request Error{} : {}".format(response.status_code,LIST_OF_HTTP_STATUS_CODES.get(response.status_code,'Unknown')))
        except Exception as e:
            print(e)
        finally:
            return ret

    # Private
    def behaviour(self, hash, dst_path) :
        ret = False
        params = {'apikey': self.__apikey, 'hash': hash}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        try :
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/behaviour', params=params, headers=headers)
            if response.status_code == 200 :
                response_json = response.json()
                response_code = response_json['response_code']
                if response_code == 1 :
                    print(response_json['verbose_msg'])
                    with open(os.path.join(dst_path, hash + '.json'), 'w', encoding='utf8') as f:
                        json.dump(response_json, f, ensure_ascii=False, indent=4)
                        ret = True
                elif response_code == 0 :
                    print(response_json['verbose_msg'])

            elif response.status_code == 204:
                print('Request rate limit exceeded. You are making more requests than allowed.')
            elif response.status_code == 400:
                print('Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
            elif response.status_code == 403:
                print('Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
            else:
                print("HTTP Request Error{} : {}".format(response.status_code,LIST_OF_HTTP_STATUS_CODES.get(response.status_code,'Unknown')))
        except Exception as e :
            print(e)
        finally:
            return ret

    # Private
    def network_traffic(self, hash):
        pass

    # Private
    def search(self, query):
        pass

    # Private
    def clusters(self, date):
        pass

    # Special
    def feed(self, package):
        pass

    # Private
    def download(self, hash, dst_path) :
        ret = False
        params = {'apikey': self.__apikey, 'hash': hash}
        try :
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)
            time.sleep(INTERVAL_TIME)
            if response.status_code == 200 :
                downloaded_file = response.content
                with open(os.path.join(dst_path, hash + '.vir'), 'wb') as f :
                    f.write(downloaded_file.encode('utf-8'))
                    ret = True
            elif response.status_code == 204:
                print('Request rate limit exceeded. You are making more requests than allowed.')
            elif response.status_code == 400:
                print('Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.')
            elif response.status_code == 403:
                print('Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.')
            else:
                print("HTTP Request Error{} : {}".format(response.status_code,LIST_OF_HTTP_STATUS_CODES.get(response.status_code,'Unknown')))
        except Exception as e :
            print(e)
        finally :
            return ret

    # antivirus vendors
    def false_positives(self, limit):
        pass