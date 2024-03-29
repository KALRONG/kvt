#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import postfile, os, sys, json, urllib, urllib2

host = "www.virustotal.com"

def retrieve_url (resource, apikey):
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    parameters = {"resource": resource, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    response = response.read()
    return print_json(response, "retrieve_url") 

def send_url (url, apikey):
    url = "https://www.virustotal.com/vtapi/v2/url/scan"
    parameters = {"url": url, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    response = response.read()
    return print_json(response, "url") 

def resend_file (resource, apikey):
    url = "https://www.virustotal.com/vtapi/v2/file/rescan"
    parameters = {"resource": resource, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    response = response.read()
    return print_json(response, "resend") 

def retrieve_report (resource, apikey):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": resource, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    response = response.read()
    return print_json(response, "retrieve") 

def print_json(response, method):
    response=json.loads(response)
    
    if method in ("file", "retrieve"):   
        if response["response_code"] in (0, 1, -2):
            if response["response_code"]==0:
                response_code="File wasn't in the virus total database."
            elif response["response_code"]==1:
                response_code="File was already in the virus total database."
            elif response["response_code"]==-2:
                response_code="File is still queued for scanning."
            else:
                return "An error has happened" 
            print "Response code: "+response_code
            print "Verbose Message: "+response["verbose_msg"]
            print "Resource: "+response["resource"]
            print "Scan Id: "+response["scan_id"]
            print "Permalink: "+response["permalink"]
            print "Hashes:"
            print "\tSHA256: "+response["sha256"]
            print "\tSHA1: "+response["sha1"]
            print "\tMD5: "+response["md5"]
            if method=="retrieve":
                print "Scan date: "+response["scan_date"]
                print "Positives: "+str(response["positives"])+"/"+str(response["total"])
                print "Scanners:\n"
    
                for fields in response["scans"]:
                    print fields+":"
                    for scan in response["scans"][fields]:
                        print "\t"+scan.title()+":"+str(response["scans"][fields][scan])
    elif method in ("resend"):
        if response["response_code"] in (0, 1, -1):
            if response["response_code"]==0:
                response_code="File wasn't in the virus total database."
            elif response["response_code"]==1:
                response_code="File succesfully queued for rescaning."
            elif response["response_code"]==-1:
               return "Unexpected Error"
            else:
                return "An error has happened"
            print "Response code: "+response_code
            print "Resource: "+response["resource"]
            print "Scan Id: "+response["scan_id"]
            print "Permalink: "+response["permalink"]
            print "Hashes:"
            print "\tSHA256: "+response["sha256"]
    elif method in ("url", "retrieve_url"):
        if response["response_code"] in (0, 1, -2):
            if response["response_code"]==0:
                response_code="Url wasn't in the virus total database."
            elif response["response_code"]==1:
                response_code="Url was already in the virus total database."
            elif response["response_code"]==-2:
                response_code="Url is still queued for scanning."
        else:
            return "An error has happened" 
        print "Response code: "+response_code
        print "Verbose Message: "+response["verbose_msg"]
        print "Resource: "+response["resource"]
        print "Url: "+response["url"]
        print "Scan Id: "+response["scan_id"]
        print "Scan date: "+response["scan_date"]
        print "Permalink: "+response["permalink"]
        if method=="retrieve_url":
            print "Positives: "+str(response["positives"])+"/"+str(response["total"])
            print "Scanners:\n"
    
            for fields in response["scans"]:
                print fields+":"
                for scan in response["scans"][fields]:
                    print "\t"+scan.title()+":"+str(response["scans"][fields][scan])
    else:
        return "An error has happened"
    return response["response_code"], response["resource"]  

def send_file(file_path, file_name, fields):
    selector = "https://www.virustotal.com/vtapi/v2/file/scan"
    file_to_send = open(file_path, "rb").read()
    files = [("file", file_name, file_to_send)]
    json = postfile.post_multipart(host, selector, fields, files)
    return print_json(json, "file")

def file_is_there(file):
    
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    
    if os.path.isfile(file) != True:
        if os.path.isfile(os.path.join(__location__, file)) == True:
            return os.path.join(__location__, file)
        else:
            print "File not found..."
            sys.exit(1)
    else:
        return file


def load_api_key (api_file):
    
    print "Trying to load keys from file: "+api_file
    
    api_file=open(file_is_there(api_file), "r")

    private_yes=False
    free_yes=False

    for line in api_file:
        buff=line.split(",")
        if buff[0] == "free":
            if buff[1] != "none": 
                if free_yes==True:
                    print "Multiple free api keys found, using first..."
                    continue
                else:                    
                    free_api=buff[1]
                    free_yes=True
        elif buff[0] == "private":
            if buff[1] != "none":
                if free_yes==True:
                    print "Multiple private api keys found, using first..."
                    continue
                else:
                    private_yes=True
                    private_api=buff[1]
                
    if private_yes==True:
        if free_yes==True:
            print "Private key found, will use it instead of free key..."
            apikey=private_api
        else:
            print "Private key found..."
            apikey=private_api
    elif free_yes==True:
        print "Free key found..."
        apikey=free_api
    else:
        print "No valid api found..."
        sys.exit(1)
    print "Using api key: "+apikey+"\n"
    api_file.close()
    return apikey



    