import kvt_functions, argparse, sys, ntpath

parser = argparse.ArgumentParser(description='Call virustotal api.')
parser.add_argument('-af','--api-key-file', default='api_keys.txt',
                   help='file that contains the api keys (default: api_keys.txt).')
parser.add_argument('-a', '--api-key',
                    help='specify the api key you want to use directly.')
parser.add_argument('-f','--file',
                    help='file to be scanned.')
parser.add_argument('-u','--url',
                    help='url to be scanned.')

args = parser.parse_args()


if len(sys.argv) == 1:
    parser.print_help()
else:
    print "Welcome to KVT!\n"
    if args.api_key == None:
        apikey=kvt_functions.load_api_key(args.api_key_file).rstrip('\n')
    else:
        apikey=args.api_key
        print "Api key specified on arguments..."
        print "Using api key: "+apikey+"\n"
    fields = [("apikey", apikey )]
    if args.file != None:
        file_path=kvt_functions.file_is_there(args.file)
        file_name=ntpath.basename(args.file)
        print "Sending file "+file_name+"...\n"
        reply=kvt_functions.send_file(file_path, file_name, fields)
        if reply[0]==1:
            print "\nFile was already scanned, getting the latest report...\n"
            kvt_functions.retrieve_report(reply[1], apikey)
            option=raw_input("Do you want to [r]esend the file again or [e]xit?")
            while option not in ("e", "r"):
                print "Invalid option"
                option=raw_input("Do you want to [r]esend the file again or [e]xit?")
            if option=="r":
                print "Resending the file...\n"
                kvt_functions.resend_file(reply[1], apikey)
            elif option=="e":
                sys.exit(0)
    elif args.url!=None:
        print "Sending url "+args.url+" ..."
        kvt_functions.send_url(args.url, apikey)
        