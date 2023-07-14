import os
import subprocess
import shutil

# the website to download
class directoryListing:

    def get_dir_structure(self, url):
        website = url
        protocol = ''
        if website.startswith('http://'):
            protocol = 'http://'
        elif website.startswith('https://'):
            protocol = 'https://'

        # Remove the "http://" or "https://"
        website_without_http = website.replace("http://", "").replace("https://", "")

        # Location to save the files. This will save in a "dirstruct" directory under your current working directory
        path_to_save = f'dirstruct/{website_without_http}'

        # Create the directory if it does not exist
        os.makedirs(path_to_save, exist_ok=True)

        # Use wget to download the website's content // add "-l", "3" in array to set the depth of scan to 3
        subprocess.run(["wget", "-t", "3", "--mirror", "--no-parent", 
                "--adjust-extension", "--convert-links", "--no-clobber", 
                "-P", path_to_save, website])



       # List to store all directories
        all_files = []

        # Use os.walk to parse the directory structure
        for dirpath, dirnames, filenames in os.walk(path_to_save):
            for dirname in dirnames:
                all_files.append(os.path.join(dirpath, dirname).replace(f'dirstruct/{website_without_http}/', protocol, 1))
            for filename in filenames:
                # Append only directories, remove the prefix
                all_files.append(os.path.join(dirpath, filename).replace(f'dirstruct/{website_without_http}/', protocol, 1))

        # Print the directories
        # for directory in all_files:
        #     print(directory)


        # Remove the downloaded content
        shutil.rmtree(path_to_save)

        return all_files

def listDirectory(url):
    lister = directoryListing()
    return lister.get_dir_structure(url)

# print(listDirectory('https://darkwebscanner.mackstathis.dev'))
