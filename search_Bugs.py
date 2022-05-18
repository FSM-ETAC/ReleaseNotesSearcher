# Name: Juan Cabrera
# Date Created: 05/16/2022
# Purpose: To search the release notes for known bugs using keywords


import json,re,os

urls = {
    "6.5.0" : "https://docs.fortinet.com/document/fortisiem/6.5.0/release-notes/482665/whats-new-in-6-5-0",
    "6.4.0" : "https://docs.fortinet.com/document/fortisiem/6.4.0/release-notes/456886/whats-new-in-6-4-0",
    "6.3.2" : "https://docs.fortinet.com/document/fortisiem/6.3.2/release-notes/803208/whats-new-in-6-3-2",
    "6.3.1" : "https://docs.fortinet.com/document/fortisiem/6.3.1/release-notes/330225/whats-new-in-6-3-1",
    "6.3.0" : "https://docs.fortinet.com/document/fortisiem/6.3.0/release-notes/498610/whats-new-in-6-3-0",
    "6.2.1" : "https://docs.fortinet.com/document/fortisiem/6.2.1/release-notes/498610/whats-new-in-6-2-1",
    "6.2.0" : "https://docs.fortinet.com/document/fortisiem/6.2.0/release-notes/498610/new-features",
    "6.1.1" : "https://docs.fortinet.com/document/fortisiem/6.1.1/release-notes/965243/whats-new-in-6-1-1#What's_New_in_6.1.1",
    "6.1.0" : "https://docs.fortinet.com/document/fortisiem/6.1.0/release-notes/441737/whats-new-in-6-1-0#What's_New_in_6.1.0"
}

class extract:
    @staticmethod
    def get_page(url):
        import urllib.request
        fp = urllib.request.urlopen(url)
        mystr = fp.read().decode("utf8")
        fp.close()
        return mystr

    @staticmethod
    def get_cache(data_file):
        with open(data_file) as f:
            data = json.load(f)
        return data

    @staticmethod
    def get_data(data, version):
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
        found = list()
        for bug in data[version]:
            if keyword in str(bug).lower():
                found.append(bug)
        return found



class load():
    @staticmethod
    def write_file(parsed_data):
        with open("cache.txt", "w") as json_Cache:
            json_Cache.write(json.dumps(parsed_data, indent=4))

    def print_found(results):
        print("{:<10} {:<15} {:<22} {:<10}".format('Bug ID', 'Severity', 'Module', 'Description'))
        print("{:<10} {:<15} {:<22} {:<10}".format('------', '--------', '------', '-----------'))
        for bug in results:
            vals = bug.values()
            list(vals)
            print ("{:<10} {:<15} {:<22} {:<10}".format(list(vals)[0], list(vals)[1], list(vals)[2], list(vals)[3]))
        print(" ")



while True:
    keyword = input("Enter keyword to search for [Type quit or 'q' to exit]: ").lower()
    if keyword.lower() == "quit" or keyword.lower() == "q":
        break
    version = input("Enter the lowest version you would like to include in the search [Please use format 6.x.x] ")
    if version.lower() == "quit" or version.lower() == "q":
        break
    elif version in ["6.1.2", "6.3.3"]:
        print(" ")
        print("================================================")
        print("This version does not have any bugs listed.")
        print("================================================")
        print(" ")
    elif version not in urls.keys():
        print(" ")
        print("================================================")
        print("The version you entered is not valid. Only versions 6.1.0 and higher are supported.")
        print("================================================")
        print(" ")
    else:
        versions_list = list(urls.keys())
        version_index = versions_list.index(version)
        relevant_versions = versions_list[0:version_index+1]

        if os.path.exists("cache.txt") == True:
            file_data = extract.get_cache("cache.txt")
            for version in relevant_versions:
                print(" ")
                print(f"============ BUGs found in Version {version} ============")
                if version in file_data.keys():
                    results = transform.get_bugs(file_data, keyword, version)
                    load.print_found(results)

                else:
                    results = extract.get_data(file_data, version)
                    load.print_found(results)
            load.write_file(file_data)

        else:
            file_data = dict()
            for version in relevant_versions:
                print(" ")
                print(f"============ BUGs found in Version {version} ============")
                results = extract.get_data(file_data, version)
                load.print_found(results)
            load.write_file(file_data)