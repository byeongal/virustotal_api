import requests, json, os, time

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
    def __init__(self, api_key) :
        self.__api_key = api_key

    # Public, Private
    def sending_and_scanning_file(self, src_path) :
        ret = False
        if os.path.getsize(src_path) >= 32000000:
            print('File size limit is 32MB')
            return ret
        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            params = {'apikey': self.__api_key}
            src_path = src_path.replace(os.sep, '/')
            with open(src_path, 'rb') as f:
                files = {'file': (src_path, f)}
                response = requests.post(url, files=files, params=params)
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

    # Public, Private
    def rescanning_already_submitted_files(self, hash_str):
        ret = False
        params = {'apikey': self.key, 'resource': hash_str}
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

    def retrieving_file_scan_report(self, hash_str, dst_path):
        ret = False
        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': self.key, 'resource': hash_str}
            response = requests.get(url, params=params)
            time.sleep(INTERVAL_TIME)
            if response.status_code == 200:
                response_json = response.json()
                response_code = response_json['response_code']
                if response_code == 1:
                    print(response_json['verbose_msg'])
                    with open(os.path.join(dst_path, hash_str + '.json'), 'w', encoding='utf8') as f:
                        json.dump(response.json(), f, ensure_ascii=False, indent=4)
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