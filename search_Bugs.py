#! python3
# Date Created: 05/16/2022
# Purpose: To search the release notes for known bugs using keywords
#
# Version History
# 2.2.2     2023-03-13      JC      Added additional parsing for 6.7.1 data.
# 2.2       2022-12-16      amm     Automatically flush local cache if server URLs list is newer; improved cache error handling
# 2.1.1     2022-12-16      amm     Fixed bug in remote URLs list processing
# 2.1       2022-11-30      amm     Testing, usability, polish
# 2.0       2022-11-23      amm     Remote release notes list
# 1.1       2022-11-22      JC      Added recent releases
# 1.0       2022-05-16      JC      Initial version

import json
import re
import os
from os.path import abspath
import sys
import errno        # For Linux-consistent exit codes
import argparse
import datetime
import urllib.request
import urllib.response
import urllib.error
from inspect import getsourcefile

#############################################################
#
# Manifest constants
#
#############################################################

OUR_VERSION="2.2.2"
PYTHON_MIN_VERSION = 3      # We need Python 3 or later
PYTHON_MIN_MINOR_VERSION = 9    # We need Python 3.9 or later


# Which version of Python is running us? We need at least Python 3.9
if sys.version_info.major < PYTHON_MIN_VERSION:
    print("You need to use Python %d or newer for this tool; you're running %s" %
        (PYTHON_MIN_VERSION,  sys.version), file=sys.stderr)
    exit(errno.EINVAL)
else:
    if sys.version_info.major == PYTHON_MIN_VERSION:
        if sys.version_info.minor < PYTHON_MIN_MINOR_VERSION:
            print("You need to use Python %d.%d or newer for this tool; you're running %s" %
                (PYTHON_MIN_VERSION, PYTHON_MIN_MINOR_VERSION,  sys.version),  file=sys.stderr)
            exit(errno.EINVAL)

import zoneinfo     # Introduced in Python 3.9

#
# Order in the following dictionary does not matter. We sort (reverse) after we get everything
# read and set, below.
#
DEFAULT_URLS = {
    "6.7.2" : "https://docs.fortinet.com/document/fortisiem/6.7.2/release-notes/561284/whats-new-in-6-7-2",
    "6.7.1" : "https://docs.fortinet.com/document/fortisiem/6.7.1/release-notes/148168/whats-new-in-6-7-1",
    "6.6.2" : None,
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


DEFAULT_URLS_HOST = "raw.githubusercontent.com"
DEFAULT_URLS_PATH = "FSM-ETAC/ReleaseNotesSearcher/main"
DEFAULT_URLS_FILE = "search_Bugs_URLs.json"
DEFAULT_URLS_URI = "https://" + DEFAULT_URLS_HOST + "/" + DEFAULT_URLS_PATH + "/" + DEFAULT_URLS_FILE
# https://raw.githubusercontent.com/FSM-ETAC/ReleaseNotesSearcher/main/search_Bugs_URLs.json

DEFAULT_CACHE_FILE = "cache.json"
DEFAULT_METADATA_FILE = "cache_metadata.json"

CACHE_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"
CACHE_DATE_FORMAT_ALT = "%Y-%m-%dT%H:%M:%S.%f"  # On the off chance that the datetime being parsed has no TZ info
BRESHIT = datetime.datetime(1,  1,  1,  0,  0,  0,  0, zoneinfo.ZoneInfo("GMT"))

# XXX With proper abstraction, this will be hidden inside the class definition.
cache_info = {
    "dataFile" : DEFAULT_CACHE_FILE,    # Name of our cache file
    "dataDate" : None,          # Date our cache file was last updated
    "URLsFile" : DEFAULT_URLS_FILE,   # Name of the Release Notes info cache file
    "URLsDate" : None,          # Date our Release Notes info cache file was last updated
    "URLsURI" : DEFAULT_URLS_URI,   # URI for the Release Notes info
    "CacheMetaData" : DEFAULT_METADATA_FILE,
    "DateFormat" : CACHE_DATE_FORMAT # Format for the datetime strings
}

class extract:
    @staticmethod
    def get_page(url):
        # Get HTML page and return it as a string
        fp = urllib.request.urlopen(url)
        mystr = fp.read().decode("utf8")
        fp.close()
        return mystr

    @staticmethod
    def get_cache(cache_info, remote_timestamp):
        # Open cache file, validate currency, and return it as a dictionary
        metadata_file = cache_info["CacheMetaData"]
        data_file = cache_info["dataFile"]
        try:
            with open(metadata_file) as mdf:
                try:
                    metadata = json.load(mdf)
                except json.decoder.JSONDecodeError:
                    print("Warning: local cache metadata (%s) has invalid format;" % metadata_file,  file=sys.stderr)
                    print("regenerating cache.",  file=sys.stderr)
                    metadata = None
                except:
                    print("Got unexpected error in json.load of metadata file %s" % data_file,  file=sys.stderr)
                    metadata = None
        except PermissionError:
            print("Permission error reading cache metadata file (%s)" % metadata_file,  file=sys.stderr)
            metadata = None
        except FileNotFoundError:
            metadata = None
        try:
            with open(data_file) as f:
                try:
                    data = json.load(f)
                except json.decoder.JSONDecodeError:
                    print("Warning: local cache (%s) has invalid format;" % data_file,  file=sys.stderr)
                    print("regenerating cache.",  file=sys.stderr)
                    data = None
                except:
                    print("Encountered an unexpected error in json.load of data file %s" % data_file,  file=sys.stderr)
                    data = None
        except PermissionError:
            print("Permission error reading cache file (%s)" % data_file,  file=sys.stderr)
            data = None
        except FileNotFoundError:
            data = None
        
        if type(metadata) == "list":
            metadata = metadata[0]      # Old caches made metadata an array of a dictionary
        if metadata is not None:
            if "DateFormat" in cache_info:
                cacheDateFormat = cache_info["DateFormat"]
            else:
                cacheDateFormat = CACHE_DATE_FORMAT
            try:
                cache_timestamp = datetime.datetime.strptime(metadata["dataDate"],  cacheDateFormat)
            except ValueError:
                try:
                    tmp = datetime.datetime.strptime(metadata["dataDate"],  CACHE_DATE_FORMAT_ALT)
                    cache_timestamp = tmp.replace(tzinfo=zoneinfo.ZoneInfo("GMT"))
                except Exception as e:
                    print("Warning: could not parse cache's timestamp (%s)" % metadata["dataDate"], file=sys.stderr)
                    print("\tRecommend flushing caches\n", file=sys.stderr)
                    print("\tGeek debugging info: exception was %s" % e)
                    cache_timestamp = datetime.datetime.now(zoneinfo.ZoneInfo("GMT"))        # Need to use this instead of utcnow() to get a tz-aware datetime.
        else:
            cache_timestamp = BRESHIT

        # XXX
        # This cache management should be fully hidden within a cache abstraction. There might be a better place for it,
        # even with the current cache management scheme.
        # XXX

        # Is the cache older than the URLs timestamp? If so, invalidate it. This ensures that the cache is updated
        # if the URLs list is updated.
        # urls_timestamp is either the relevant timestamp info from the metadata file, if we're using the server's
        # URLs list, or the modification time of this program file.

        if cache_timestamp < remote_timestamp:  # Cache is obsolete
            extract.flush_caches(cache_info)
            allData = None
        else:
            allData = {
                "metadata" : metadata,
                "data" : data
            }
        return allData

    @staticmethod
    def flush_caches(caches_info):
        # The purpose is to remove the cache. So, if there's no cache, we don't care: it's deemed removed.
        # However, we still need to handle permission problems!
        try:
            if os.path.isfile(caches_info["dataFile"]):
                os.remove(caches_info["dataFile"])
        except PermissionError:
            print("No permission to remove data cache %s" % caches_info["dataFile"],  file=sys.stderr)
        except Exception as e:
            print("Error (%s) attempting to flush data cache %s" % (e, caches_info["dataFile"]), file=sys.stderr)
        caches_info["dataDate"] = None

        try:
            if os.path.isfile(caches_info["CacheMetaData"]):
                os.remove(caches_info["CacheMetaData"])
        except PermissionError:
            print("No permission to remove metadata cache %s" % caches_info["CacheMetaData"],  file=sys.stderr)
        except Exception as e:
            print("Error (%s) attempting to flush metadata cache %s" % (e, caches_info["CacheMetaData"]), file=sys.stderr)
        caches_info["dataDate"] = None
        caches_info["CacheMetaData"] = None

    @staticmethod
    def get_data(data, version):
        # When version is not in cache, call get_page and clean_data for missing version.
        if urls[version] is None:
            return
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
        # Takes HTML data string as input and returns a list of dictionaries where each dictionary is a bug.
        index_start = re.search("<p>\d{6}</p>|\">\d{6}</td>", data).start()
        index_end = re.search(".*  </td>\r\n.*</tr>\r\n.*</tbody>", data).start()
        short_data = data[index_start:index_end-1]
        # Special case for 6.7.1 data parsing. Original regex was capturing "<p>&nbsp;</p>" as a value.
        if version == "6.7.1":
            values = re.findall("System</td>|<p>.*\r\n.*</p>\r\n.*<p><b>Note</b>.*\r\n.*</p>|<p>[A-Za-z0-9].*</p>|<p>.*\n.*</p>|<p>.*\n.*\n.*</p>|<p>.*\n.*\n.*\n.*</p>|<p>.*\n.*\n.*\n.*\n.*</p>", short_data)
        else: 
            values = re.findall("<p>.*\r\n.*</p>\r\n.*<p><b>Note</b>.*\r\n.*</p>|<p>.*<\/p>|<p>.*\n.*</p>|<p>.*\n.*\n.*</p>|<p>.*\n.*\n.*\n.*</p>|<p>.*\n.*\n.*\n.*\n.*</p>|AD.Server.</td>\n.*</tr>", short_data)
        if version == "6.3.1":
            values.insert(3, "<p>In AD User Discovery, the Last Login Value was incorrect if the user was not set (did not log in) to the AD Server.</p>")
        cleaned_values = list()
        columns = ["Bug ID", "Severity", "Module", "Description"]
        for x in range(0, len(values), 4):
            bug_list = list()
            for i in range(x, x+4):
                val = values[i]
                for ch in ["<p>", "</p>", "\r\n", "<code>", "</code>", "&nbsp;", "<b>", "</b>", "&gt;", "</td>"]:
                    if ch in val:
                        val = val.replace(ch,"")
                spaces_cleaned = ' '.join(val.split())
                bug_list.append(spaces_cleaned)
            bug_dict = {columns[i]: bug_list[i] for i in range(len(columns))}
            cleaned_values.append(bug_dict)
        final_values = {version : cleaned_values}
        return final_values

    @staticmethod
    def clean_data_6_1(data, version):
        # Takes HTML data string as input and returns a list of dictionaries where each dictionary is a bug. For 6.1.x versions due to different HTML format.
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
        final_values = {version : cleaned_values}
        return final_values

    @staticmethod
    def get_bugs(data, keyword, version):
        # Searches dictionary of the data from cache with the passed keyword and returns a list of matching bugs.
        found = list()
        for bug in data[version]:
            if keyword in str(bug).lower():
                found.append(bug)
        return found


class load():
    @staticmethod
    def write_file(parsed_data):
        # Opens new or overwrites current cache file and writes the list of dictionaries (bugs) into it.

        if cache_info["dataFile"] == None:
            cache_info["dataFile"] = DEFAULT_CACHE_FILE
        if cache_info["CacheMetaData"] == None:
            cache_info["CacheMetaData"] = DEFAULT_METADATA_FILE

        try:
            with open(cache_info["dataFile"], "w") as json_Cache:
                json_Cache.write(json.dumps(parsed_data, indent=4))
            cache_info["dataDate"] = datetime.datetime.utcnow().isoformat()    # There's no JSON serializer for datetime
            cache_info["URLsDate"] = urls_timestamp_stg
        except PermissionError:
            print("Permission error writing cache file (%s)" % cache_info["dataFile"],  file=sys.stderr)
            return False
        try:
            with open(cache_info["CacheMetaData"],  "w") as metaDataCache:
                metaDataCache.write(json.dumps(cache_info,  indent=4))
        except PermissionError:
            print("Permission error writing metadata file (%s)" % cache_info["CacheMetaData"],  file=sys.stderr)
            return False
        return True

    def print_found(results):
        # Prints search results in a formatted table.
        print("{:<10} {:<15} {:<22} {:<10}".format('Bug ID', 'Severity', 'Module', 'Description'))
        print("{:<10} {:<15} {:<22} {:<10}".format('------', '--------', '------', '-----------'))
        for bug in results:
            vals = bug.values()
            list(vals)
            print ("{:<10} {:<15} {:<22} {:<10}".format(list(vals)[0], list(vals)[1], list(vals)[2], list(vals)[3]))
        print(" ")


def processArgs():
    #
    # Process command-line arguments
    #
    
    argParser = argparse.ArgumentParser(description="Search FortiSIEM release notes for fixed bugs")
    argParser.add_argument("-f", "--flush", action="store_true", default=False, help="Flush caches (both data and locations)")
    argParser.add_argument("-c",  "--check_caches",  action="store_true",  default=False, help="Check whether caches are current")
    argParser.add_argument("-s", "--start_version", nargs=1, default=False, help="Starting (oldest) version to search")
    argParser.add_argument("-t", "--list_versions", action="store_true", default=False, help="List available versions (and exit)")
    argParser.add_argument("-u", "--urls_uri", nargs=1, default=[cache_info["URLsURI"]], help="URI of the URLs data (fixed bugs list in release notes)")
    argParser.add_argument("--metaDataFile",  nargs=1, default=cache_info["CacheMetaData"], help="Cache metadata file")
    argParser.add_argument("-G", "--generateURLsFile", action="store_true",  default=False,  help="Generate the URLs file (json)")
    if sys.version_info.minor < 8:
        # The 'extend' action came in Python 3.8. If we're running an earlier version, we still want to be able to work, just
        # not quite as robustly.
        argParser.add_argument("-k", "--keyword",  nargs=1,  default=None, help="Keyword to find")
    else:
        argParser.add_argument("-k", "--keyword", nargs=1, action="extend", default=None, help="Keyword to find")
    argParser.add_argument("--version", action="version", version="%(prog)s Version " + OUR_VERSION +
        " (Python %d.%d.%d)" % (sys.version_info.major, sys.version_info.minor, sys.version_info.micro),  help="Report the version of this program")
    return argParser.parse_args()

return_code = 0

args = processArgs()

# Does the user want to flush the caches?
if args.flush:
    extract.flush_caches(cache_info)
    print("Caches flushed, per request")
    # XXX Semantic question: should -f alone on the CLI exit, or should we enter the read-execute loop and
    # ask the user for input, as if we'd had no CLI args? For now, we'll continue into the read-execute loop

# Does the user want to check whether the caches are current?
if args.check_caches:
    # The data cache is deemed current if it's no older than the Release Notes info data (i.e., the URLs)
    print("Cache currency check not yet implemented")  # XXX
    
# args.urls_uri has the URI of our URLs database (json). Attempt to read from there. If we can't, we'll use
# the default (DEFAULT_URLS).
urls_uri = args.urls_uri[0]
urls = None
try:
    urlFile = urllib.request.urlopen(urls_uri)
    augmented_urls = json.loads(urlFile.read())
    urls_timestamp_stg = augmented_urls["Time"]
    urls = augmented_urls["URLs Data"]
except urllib.error.HTTPError as err:   # We got some kind of HTTP error.
    if 404 == err.code:     # 404: target URI not found.
        print("Warning: Release Notes info location %s not found, using built-in info." % urls_uri, file=sys.stderr)
        return_code = errno.ENODATA
        urls = None
    else:       # The HTTP error wasn't a "simple" 404. Still, treat it about the same way.
        print("Warning: Unable to read Release Notes info location %s." % urls_uri, file=sys.stderr)
        print(err, file=sys.stderr)
        print("Using built-in Release Notes info location.", file=sys.stderr)
        return_code = errno.ENODEV
        urls = None
except urllib.error.URLError as err:    # Error isn't an "HTTP" error, but there's still something wrong.
    print("Error accessing Release Notes info location %s.\n%s." % (urls_uri, err.reason.strerror), file=sys.stderr)
    print("Using built-in Release Notes info location.", file=sys.stderr)
    return_code = err.reason.errno
    urls = None
except ValueError:      # Includes JSONDecodeError, which means the JSON we read isn't valid
    print("Cannot decode Release Notes locations file at %s; using default info." % urls_uri, file=sys.stderr)
    return_code = errno.EILSEQ
    urls = None
except:         # Let's cover everything with a catch-all.
    print("Unexpected error reading Release Notes locations file at %s; using default info" % urls_uri, file=sys.stderr)
    return_code = errno.EFAULT
    urls = None

if urls is None:
    # Sort the URLs by descending key.
    urls = {key: val for key, val in sorted(DEFAULT_URLS.items(), key = lambda x: x[0], reverse = True)}
    ourFile = abspath(getsourcefile(lambda:0))
    urls_timestamp = datetime.datetime.utcfromtimestamp(os.path.getmtime(ourFile))
    augmented_urls = {"Time" : urls_timestamp.isoformat(),  "URLs Data" : urls}
    
else:
    tmp = {key: val for key, val in sorted(urls.items(), key = lambda x: x[0], reverse = True)}
    urls = tmp


# Shall we output the URLs file (json)?
if args.generateURLsFile:
    print(json.dumps(augmented_urls, indent=4))
    exit(0)

# Get our list of versions. We will need some of this, might need the rest, later, easier just to generate it now.
versions_list = list(urls.keys())
versions_string = " ".join(versions_list)
minimum_version = versions_list[len(urls)-1]

# List the valid versions?
if args.list_versions:
    print("Versions available: %s\n" % versions_string)
    exit(return_code)
    
#
# Read the user's keyword and minimum version. Find the fixed bugs in the release notes.
# Continue until q or quit or EOF
#
printedKeyword = False
printedVersion = False
versionValid = False
interactive = [False, False]         # We'll assume we have both version and keyword from the CLI
oldest_version = None

while True:
    if args.keyword is None or interactive[0]:    # No keywords from CLI; prompt for one
        interactive[0] = True
        try:
            keyword = input("Enter keyword to search for [type quit or 'q' to exit]: ").lower()
        except EOFError:
            print("Exiting per EOF")
            exit(return_code)
        except KeyboardInterrupt:
            print("Received keyboard interrupt, exiting")
            exit(errno.EINTR)
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
            print("Searching for fixed bugs mentioned in release notes that match '%s'." % keyword)
            printedKeyword = True

    while (oldest_version is None):
        if args.start_version is None or (not args.start_version) or interactive[1]:  # No version on CLI; prompt for one
            interactive[0] = True
            try:
                oldest_version = input("Enter the lowest version you would like to include in the search [use format x.y.z; minimum %s]: " % minimum_version)
            except EOFError:
                print("Exiting per EOF")
                exit(return_code)
            if "" == oldest_version or oldest_version.lower() == "quit" or oldest_version.lower() == "q":
                print ("Exiting per request")
                exit(return_code) 
        else:
            if not printedVersion:
                oldest_version = args.start_version[len(args.start_version)-1]
                print("Searching versions starting with %s." % oldest_version)
                printedVersion = True
                interactive[1] = True;	# When no keyword on CLI, allow new version input on next iteration.
    
        if oldest_version not in versions_list:
            print(" ")
            print("================================================")
            print("The version you entered (%s) is not available. Available versions are\n%s." % (oldest_version, versions_string))
            print("================================================")
            print(" ")
            if not (args.start_version is None or (not args.start_version)):
                # If version came from CLI and isn't available, exit now.
                exit(errno.EDOM)
            else:
                oldest_version = None

    else:       # We have a valid, known version. Look for the fixed bugs.
        version_index = versions_list.index(oldest_version)
        relevant_versions = versions_list[0:version_index+1]
        cached_data = None
        file_data = None
        caught_error = False
        try:
            cached_data = extract.get_cache(cache_info, datetime.datetime.strptime(urls_timestamp_stg, cache_info["DateFormat"]))   # Get the locally-cached data
        except:
            print("Unable to parse timestamp %s (used %s)" % (urls_timestamp_stg, cache_info["DateFormat"]), file=sys.stderr)
            print("Using local URIs data")
            cached_data = None
        if cached_data is None:
            return_code = errno.EBADF
            file_data = None
        else:
            metadata = cached_data["metadata"]
            file_data = cached_data["data"]
        if file_data is not None:
            for v in relevant_versions:
                if urls[v] is None:
                    print("Skipping %s: no fixed bugs listed in release notes\n" % v)
                else:
                    if v in file_data.keys():
                        results = transform.get_bugs(file_data, keyword, v)
                        if results is not None and 0 != len(results):
                            print(f"============ Fixed Bugs Found in Version {v} Release Notes ============")
                            load.print_found(results)
                        else:
                            print("No matching fixed bugs found in %s release notes\n" %v)
    
                    else:
                        results = extract.get_data(file_data, v)
                        if results is not None and 0 != len(results):
                            print(f"============ Fixed Bugs Found in Version {v} Release Notes ============")
                            load.print_found(results)
                        else:
                            print("No matching fixed bugs found in %s release notes\n" % v)

            if not load.write_file(file_data):
                print("Caching error; check other messages, check file permissions and ownership", file=sys.stderr)
                return_code = errno.EBADF

        else:       # No valid cache; build it.
            # Note that we build the cache file incrementally. If the user doesn't ask for fixes in version x.y.z,
            # we won't fetch those data at all, and so we don't cache them.
            file_data = dict()
            for v in relevant_versions:
                if urls[v] is None:
                    print("Skipping %s: no fixed bugs listed in release notes\n" % v)
                else:
                    results = extract.get_data(file_data, v)
                    if results is not None and 0 != len(results):
                        print(f"============ Fixed Bugs Found in Version {v} Release Notes ============")
                        load.print_found(results)
                    else:
                        print("No matching fixed bugs found in %s releases notes\n" %v)

                    if not load.write_file(file_data):
                        print("Caching error; check other messages, check file permissions and ownership",  file=sys.stderr)
                        return_code = errno.EBADF
    if not interactive[0]:
        exit(return_code)
