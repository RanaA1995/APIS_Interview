import csv
import requests
from virustotal_python import Virustotal
from virustotal_python import VirustotalError
import validators
import json
import time

api_key = 'da7cc2796655432b01de46d4bb20856b5ba4cd2405b36a47f3304e1fc7223bcf'


def scan(url_batch, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    scan_id_list = []
    for URL in url_batch:
        try:
            params = {'apikey': api_key, 'url': URL}
            response = requests.post(url, data=params)
            check_respond(response)
            scan_id_list.append(response.json()['scan_id'])
        except ValueError as e:
            print(e)
            continue
        except Exception:
            print(e)
            continue
    return scan_id_list


def report(scan_id_list, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    report_list = []
    for id in scan_id_list:
        try:
            params = {'apikey': api_key, 'resource': id}
            response = requests.get(url, params=params)
            report_list.append(response.json())
        except ValueError as e:
            print(e)
            continue
        except Exception:
            print(e)
            continue
    return report_list

def main():
    url_list = []
    output_file = open("result_file.txt", "a")
    response_file = open("respond_file.txt", 'a')

    ########### retieving data from CSV file URL.
    CSV_URL = 'https://elementor-pub.s3.eu-central-1.amazonaws.com/Data-Enginner/Challenge1/request1.csv'
    with requests.Session() as s:
        download = s.get(CSV_URL)
        decoded_content = download.content.decode('utf-8')
        cr = csv.reader(decoded_content.splitlines(), delimiter=',')
        my_list = list(cr)
        for row in my_list:
            url_list.append(row)
        response = []
        report_list = []
        for i in range(len(url_list)):
            if i % 4 == 0:
                # suppposed to be 30 minutes for refreshed updated ..!!
                time.sleep(120)
                url_batch = []
            url_batch.append(url_list[i])
            if i % 4 == 3 or i == len(url_list) - 1:
                response += scan(url_batch, api_key)
                response_file.write('\n'.join(str(t) for t in response))
    print("scan is completed")
    for i in range(len(response)):
        if i % 4 == 0:
            time.sleep(60)
            scan_list = []
        scan_list.append(response[i])
        if i % 4 == 3 or i == len(response) - 1:
            reportBatch = report(scan_list, api_key)
            report_list += reportBatch
            for r in reportBatch:
                json.dump(r, output_file)
                output_file.write("\n")
    output_file.close()
    response_file.close()


main()

def check_respond(url_path, respond):
    valid = validators.url(respond)
    file = open("result_file.txt", "w")
    if valid:
        file.write(url_path + " IS      SAFE")
    else:
        file.write(url_path + " IS      RISK")
    file.close()

###############################################################################
# 200: Everything went okay, and the result has been returned (if any).
# 301: The server is redirecting you to a different endpoint. This can happen when a company switches domain names,
# or an endpoint name is changed.
# 400: The server thinks you made a bad request. This can happen when you don’t send along the right data, among other things.
# 401: The server thinks you’re not authenticated. Many APIs require login ccredentials, so this happens when you don’t
# send the right credentials to access an API.
# 403: The resource you’re trying to access is forbidden: you don’t have the right permissions to see it.
# 404: The resource you tried to access wasn’t found on the server.
# 503: The server is not ready to handle the request.
###############################################################################
