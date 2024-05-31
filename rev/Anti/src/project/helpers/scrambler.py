import os
import re

def search_in_file(file_path, pattern):
    with open(file_path, 'r') as file:
        try :
            content = file.read()
        except UnicodeDecodeError:
            return
        matches = re.findall(pattern, content)
        if matches:
            print("Matches found in '{}':".format(file_path))
            for match in matches:
                # fw, sw, tw = match
                # print("----------------------------------------------------------")
                # print("First word:", fw.strip())
                # print("Second word after the first comma:", sw.strip())
                # print("Third word after the second comma:", tw.strip())
                # print("----------------------------------------------------------")
                fw, sw, tw = match
                modified_match = "write({},{},{});".format(sw.strip(), fw.strip(), tw.strip())
                modified_content = modified_content.replace("write({}, {}, {});".format(fw.strip(), sw.strip(), tw.strip()), modified_match)

            with open(file_path, 'w') as modified_file:
                modified_file.write(modified_content)

def main():
    # could be changed depending on what you want to scramble and how you want to scramble it
    pattern = r'write\(([^,]+),([^,]+),([^,]+)\);'
    directory = "../dietlibc"
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            if file_name.endswith(".c") or file_name.endswith(".h"):
                file_path = os.path.join(root, file_name)
                search_in_file(file_path, pattern)
    

if __name__ == "__main__":
    main()