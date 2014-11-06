import postfile, os, sys, json, urllib, urllib2

host = "www.virustotal.com"

def retrieve_report (md5, apikey):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": md5, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    response = response.read()
    response=json.loads(response)
    
    if response["response_code"]==0:
            response_code="File wasn't in the virus total database."
    elif response["response_code"]==1:
            response_code="File was already in the virus total database."
    elif response["response_code"]==-2:
            response_code="File is still queued for scanning."
    else:
            return "An error has happened"
    
    print "Scan date: "+response["scan_date"]
    print "Response code: "+response_code
    print "Verbose Message: "+response["verbose_msg"]
    print "Resource: "+response["resource"]
    print "Scan Id: "+response["scan_id"]
    print "Permalink: "+response["permalink"]
    print "Hashes:"
    print "\tSHA256: "+response["sha256"]
    print "\tSHA1: "+response["sha1"]
    print "\tMD5: "+response["md5"]
    print "Positives: "+str(response["positives"])+"/"+str(response["total"])
    print "Scanners:\n"
    
    for fields in response["scans"]:
        print fields+":"
        for scan in response["scans"][fields]:
            print "\t"+scan.title()+":"+str(response["scans"][fields][scan])


def print_json(response, method):
    response=json.loads(response)
    if response["response_code"] in (0, 1, -2):
        if method=="file":
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
        return response["response_code"], response["md5"]
    else:
        return "An error has happened"
        

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



    