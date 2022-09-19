#!/usr/bin/python3

import json
import re
import os
import sys
import errno        # For Linux-consistent exit codes
import argparse

# Manifest constants
OUR_VERSION="1.1"

#
# Note: for proper semantics, the entries in urls should be in descending "numeric" order by key.
#
urls = {
    "6.6.1" : "https://docs.fortinet.com/document/fortisiem/6.6.1/release-notes/267436/whats-new-in-6-6-1",
    "6.6.0" : "https://docs.fortinet.com/document/fortisiem/6.6.0/release-notes/709914/whats-new-in-6-6-0",
    "6.5.1" : "https://docs.fortinet.com/document/fortisiem/6.5.1/release-notes/822785/whats-new-in-6-5-1",
    "6.5.0" : "https://docs.fortinet.com/document/fortisiem/6.5.0/release-notes/482665/whats-new-in-6-5-0",
    "6.4.1" : "https://docs.fortinet.com/document/fortisiem/6.4.1/release-notes/516901/whats-new-in-6-4-1",
    "6.4.0" : "https://docs.fortinet.com/document/fortisiem/6.4.0/release-notes/456886/whats-new-in-6-4-0",
    "6.3.3" : None,
    "6.3.2" : "https://docs.fortinet.com/document/fortisiem/6.3.2/release-notes/803208/whats-new-in-6-3-2",
    "6.3.1" : "https://docs.fortinet.com/document/fortisiem/6.3.1/release-notes/330225/whats-new-in-6-3-1",
    "6.3.0" : "https://docs.fortinet.com/document/fortisiem/6.3.0/release-notes/498610/whats-new-in-6-3-0",
    "6.2.1" : "https://docs.fortinet.com/document/fortisiem/6.2.1/release-notes/498610/whats-new-in-6-2-1",
    "6.2.0" : "https://docs.fortinet.com/document/fortisiem/6.2.0/release-notes/498610/new-features",
    "6.1.2" : None,
    "6.1.1" : "https://docs.fortinet.com/document/fortisiem/6.1.1/release-notes/965243/whats-new-in-6-1-1#What's_New_in_6.1.1",
    "6.1.0" : "https://docs.fortinet.com/document/fortisiem/6.1.0/release-notes/441737/whats-new-in-6-1-0#What's_New_in_6.1.0"
}

# Manifest constant
# XXX With proper abstraction, this will be hidden inside the class definition.
CACHE_FILE_NAME = "cache.txt"    # Name of our cache file

class extract:
    @staticmethod
    def get_page(url):
        #Get HTML page and return it as a string
        import urllib.request
        fp = urllib.request.urlopen(url)
        mystr = fp.read().decode("utf8")
        fp.close()
        return mystr

    @staticmethod
    def get_cache(data_file):
        #Open cache file and return it as a dictionary
        with open(data_file) as f:
            data = json.load(f)
        return data

    @staticmethod
    def flush_cache(data_file):
        # The purpose is to remove the cache. If there's no cache, we don't care: it's deemed removed.
        if os.path.isfile(data_file):
            os.remove(data_file)

    @staticmethod
    def get_data(data, version):
        #When version is not in cache, call get_page and clean_data for missing version.
        if version == "6.1.0" or version == "6.1.1":
            html_data = extract.get_page(urls[version])
            parsed_Data = transform.clean_data_6_1(html_data, version)
            data.update(parsed_Data)
            return transform.get_bugs(data, keyword, version)
        else:
            html_data = extract.get_page(urls[version])
            parsed_Data = transform.clean_data(html_data, version)
            data.update(parsed_Data)
            return transform.get_bugs(data, keyword, version)



class transform:
    @staticmethod
    def clean_data(data, version):
        #Takes HTML data string as input and returns a list of dictionaries where each dictionary is a bug. 
        index_start = re.search("<p>\d{6}</p>|\">\d{6}</td>", data).start()
        index_end = re.search(".*  </td>\r\n.*</tr>\r\n.*</tbody>", data).start()
        short_data = data[index_start:index_end-1]
        values = re.findall("<p>.*\r\n.*</p>\r\n.*<p><b>Note</b>.*\r\n.*</p>|<p>.*</p>|<p>.*\n.*</p>|<p>.*\n.*\n.*</p>|<p>.*\n.*\n.*\n.*</p>|<p>.*\n.*\n.*\n.*\n.*</p>|AD.Server.</td>\n.*</tr>", short_data)

        if version == "6.3.1":
            values.insert(3, "<p>In AD User Discovery, the Last Login Value was incorrect if the user was not set (did not log in) to the AD Server.</p>")
        cleaned_values = list()
        columns = ["Bug ID", "Severity", "Module", "Description"]
        for x in range(0, len(values), 4):
            bug_list = list()
            for i in range(x, x+4):
                val = values[i]
                for ch in ["<p>", "</p>", "\r\n", "<code>", "</code>", "&nbsp;", "<b>", "</b>", "&gt;"]:
                    if ch in val:
                        val = val.replace(ch,"")
                spaces_cleaned = ' '.join(val.split())
                bug_list.append(spaces_cleaned)
            bug_dict = {columns[i]: bug_list[i] for i in range(len(columns))}
            cleaned_values.append(bug_dict)
        final_values = { version : cleaned_values}
        return final_values

    @staticmethod
    def clean_data_6_1(data, version):
        #Takes HTML data string as input and returns a list of dictionaries where each dictionary is a bug. For 6.1.x versions due to different HTML format.
        index_start = re.search("Body1\">\r\n.*\d{6}\r\n.*</td>|Body1\">\d{6}</td>", data).start()
        index_end = re.search("details.\r\n.*</td>\r\n.*</tr>\r\n.*</tbody>|time.</td>\n</tr>\n</tbody>", data).start()
        if version == "6.1.0":
            short_data = data[index_start:index_end+35]
            values = re.findall("Body[1-2]\">\r\n.*\r\n.*</td>|Body[1-2]\">\r\n.*\r\n.*\r\n.*</td>", short_data)
        else:
            short_data = data[index_start:index_end+10]
            values = re.findall("Body1\">.*</td>|Body2\">.*</td>|Body1\">.*\r\n.*</td>|Body2\">.*\r\n.*</td>", short_data)
        cleaned_values = list()
        columns = ["Bug ID", "Severity", "Module", "Description"]
        for x in range(0, len(values), 4):
            bug_list = list()
            for i in range(x, x+4):
                val = values[i]
                for ch in ["Body1\">", "Body2\">", "<td class=\"TableStyle-FortinetTable-BodyE-Column1-", "<td class=\"TableStyle-FortinetTable-BodyB-Column1-", "</td>", "\r\n"]:
                    if ch in val:
                        val = val.replace(ch,"")
                spaces_cleaned = ' '.join(val.split())
                bug_list.append(spaces_cleaned)
            bug_dict = {columns[i]: bug_list[i] for i in range(len(columns))}
            cleaned_values.append(bug_dict)
        final_values = { version : cleaned_values}
        return final_values

    @staticmethod
    def get_bugs(data, keyword, version):
        #Searches dictionary of the data from cache with the passed keyword and returns a list of matching bugs.
        found = list()
        for bug in data[version]:
            if keyword in str(bug).lower():
                found.append(bug)
        return found



class load():
    @staticmethod
    def write_file(parsed_data):
        #Opens new or overwrites current cache.txt file and writes the list of dictionaries (bugs) into it.
        with open("cache.txt", "w") as json_Cache:
            json_Cache.write(json.dumps(parsed_data, indent=4))

    def print_found(results):
        #Prints search results in a formatted table.
        print("{:<10} {:<15} {:<22} {:<10}".format('Bug ID', 'Severity', 'Module', 'Description'))
        print("{:<10} {:<15} {:<22} {:<10}".format('------', '--------', '------', '-----------'))
        for bug in results:
            vals = bug.values()
            list(vals)
            print ("{:<10} {:<15} {:<22} {:<10}".format(list(vals)[0], list(vals)[1], list(vals)[2], list(vals)[3]))
        print(" ")

# Which version of Python is running us? We need at least Python 3.
if sys.version_info.major < 3:
    print("Please use Python 3 or newer")
    exit(errno.ENOPKG)

# Get our list of versions. We might need this later, easier just to generate it now.
versions_list = list(urls.keys())
versions_string = " ".join(versions_list)


#
# Process command-line arguments
#
argParser = argparse.ArgumentParser(description="Search FortiSIEM release notes for fixed bugs")
argParser.add_argument("-f", "--flush", action="store_true", default=False, help="Flush cache")
argParser.add_argument("-s", "--start_version", nargs=1, default=False, help="Starting (oldest) version to search")
argParser.add_argument("-t", "--list_versions", action="store_true", default=False, help="List available versions (and exit)")
if sys.version_info.minor < 8:
    # The 'extend' action came in Python 3.8. If we're running an earlier version, we still want to be able to work, just
    # not quite as robustly.
    argParser.add_argument("-k", "--keyword",  nargs="+",  default=None, help="Keyword to find")
else:
    argParser.add_argument("-k", "--keyword", nargs="+", action="extend", default=None, help="Keyword to find")
argParser.add_argument("--version", action="version", version="%(prog)s version " + OUR_VERSION)
args=argParser.parse_args()

return_code = 0

# List the valid versions?
if args.list_versions:
    print("Versions available: %s\n" % versions_string)
    exit(return_code)

# Flush the cache?
if args.flush:
    extract.flush_cache(CACHE_FILE_NAME)
    print("Cache flushed, per request")
    # XXX Semantic question: should -f alone on the CLI exit, or shold we enter the read-execute loop and
    # ask the user for input, as if we'd had no CLI args? For now, we'll continue into the read-execute loop
    
#
# Read the user's keyword and minimum version. Find the fixed bugs in the release notes.
# Continue until q or quit or EOF
#
printedKeyword = False
printedVersion = False
versionValid = False
interactive = [False, False]          # We'll assume we have both version and keyword from the CLI
      

while True:
    if args.keyword is None or interactive[0]:    # No keywords from CLI; prompt for one
        interactive[0] = True
        try:
            keyword = input("Enter keyword to search for [type quit or 'q' to exit]: ").lower()
        except EOFError:
            print("Exiting per EOF")
            exit(return_code)
        if "" == keyword or keyword.lower() == "quit" or keyword.lower() == "q":
            print("Exiting per request")
            exit(return_code)
    else:
        if not printedKeyword:
            # XXX We search just for the LAST keyword the user entered on the CLI.
            # XXX Future enhancement: iterate over ALL keywords from the CLI.
            keyword = args.keyword[len(args.keyword)-1]     # Grab just the last keyword provided
            if len(args.keyword) > 1:
                print("Warning: multiple keyword seaches from CLI not yet supported; using last keyword provided (%s)." % keyword,
                      file=sys.stderr)
                return_code = errno.EAGAIN
            print("Searching for fixed bugs matching '%s'." % keyword)
            printedKeyword = True

 
    if args.start_version is None or (not args.start_version) or interactive[1]:  # No version on CLI; prompt for one
        interactive[0] = True
        try:
            oldest_version = input("Enter the lowest version you would like to include in the search [use format 6.x.x]: ")
        except EOFError:
            print("Exiting per EOF")
            exit(return_code)  # XXX Move exit (213) to this clause of the IF-ELSE
        if "" == oldest_version or oldest_version.lower() == "quit" or oldest_version.lower() == "q":
            print ("Exiting per request")
            exit(return_code) 
    else:
        if not printedVersion:
            oldest_version = args.start_version[len(args.start_version)-1]
            print("Searching versions starting with %s." % oldest_version)
            printedVersion = True
            interactive[1] = True     # When no keyword on CLI, sets this parameter to True to allow new version input on next iteration.


    if oldest_version not in versions_list:
        print(" ")
        print("================================================")
        print(f"The version you entered {oldest_version} is not available. Available versions are\n{versions_string}.")
        print("================================================")
        print(" ")
        if not (args.start_version is None or (not args.start_version)):
            # If version came from CLI and isn't available, exit now.
            exit(errno.EDOM)
    else:       # We have a valid, known version. Look for the fixed bugs.
        version_index = versions_list.index(oldest_version)
        relevant_versions = versions_list[0:version_index+1]
        if os.path.exists(CACHE_FILE_NAME) == True:     # Cache there? If so, use it
            file_data = extract.get_cache(CACHE_FILE_NAME)
            for v in relevant_versions:
                if urls[v] is None:
                    print("Skipping %s: no fixed bugs listed in release notes\n" % v)
                else:
                    if v in file_data.keys():
                        results = transform.get_bugs(file_data, keyword, v)
                        if results is not None and 0 != len(results):
                            print(f"============ BUGs found in Version {v} ============")
                            load.print_found(results)
                        else:
                            print("No matching bugs found in %s\n" %v)
    
                    else:
                        results = extract.get_data(file_data, v)
                        if results is not None and 0 != len(results):
                            print(f"============ BUGs found in Version {v} ============")
                            load.print_found(results)
                        else:
                            print("No matching bugs found in %s\n" % v)
            load.write_file(file_data)

        else:       # No cache; build it.
            # Note that we build the cache file incrementally. If the user doesn't ask for fixes in version x.y.z,
            # we won't fetch those data at all, and so we don't cache them.
            file_data = dict()
            for v in relevant_versions:
                if urls[v] is None:
                    print("Skipping %s: no fixed bugs listed in release notes\n" % v)
                else:
                    results = extract.get_data(file_data, v)
                    if results is not None and 0 != len(results):
                        print(f"============ BUGs found in Version {v} ============")
                        load.print_found(results)
                    else:
                        print("No matching bugs found in %s\n" %v)

                    load.write_file(file_data)
    if not interactive[0]:
        exit(return_code)
