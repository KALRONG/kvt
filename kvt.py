import kvt_functions, argparse, sys, ntpath

parser = argparse.ArgumentParser(description='Call virustotal api.')
parser.add_argument('-a','--api-key-file', default='api_keys.txt',
                   help='file that contains the api keys (default: api_keys.txt)')
parser.add_argument('-f','--file',
                    help='file to be send to be processed.')

args = parser.parse_args()


if len(sys.argv) == 1:
    parser.print_help()
else:
    print "Welcome to KVT!\n"
    apikey=kvt_functions.load_api_key(args.api_key_file).rstrip('\n')
    fields = [("apikey", apikey )]
    if args.file != None:
        method="file"
        file_path=kvt_functions.file_is_there(args.file)
        file_name=ntpath.basename(args.file)
        print "Sending file "+file_name+"...\n"
        reply=kvt_functions.send_file(file_path, file_name, fields)
        if reply[0]==1:
            option=raw_input("Do you want to retrieve the existing [r]eport or [s]end the file again?")
            while option not in ("s", "r"):
                print "Invalid option"
                option=raw_input("Do you want to retrieve the existing [r]eport or [s]end the file again?")
            if option=="r":
                print "Getting the report...\n"
                kvt_functions.retrieve_report(reply[1], apikey)
            elif option=="s":
                print "send"
        