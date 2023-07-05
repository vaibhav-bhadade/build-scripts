import argparse
import shutil
import os
import tarfile
import yaml
import json
import glob
from git import Repo

 
# Global variables 
git_url = "https://575160c638b34c22dfd352ea4a081a0155d16b5b@github.ibm.com/PrivateCloud-analytics/cpd-case-repo.git"
cp4d_release = ""
cp4d_branch  = ""
cp4d_component = ""
 

# Extract All image sha values from inventory
def extract_image_and_digest_details():
    #Print Working Directory
    current_working_directory = os.getcwd()
    #If folder exist remove the folder
    #if os.path.exists(current_working_directory + "/cpd-case-repo"):
    #    shutil.rmtree(current_working_directory + "/cpd-case-repo/")
    print("cloning repo cpd-case-repo")
    #repo = Repo.clone_from(git_url, "cpd-case-repo")
    os.chdir("cpd-case-repo")
    cwd = os.getcwd()
    print("path:", cwd)
    #repo.git.checkout(user_conf['user_input']['release'])
    #os.chdir("promoted/case-repo-promoted/ibm-wsl/6.4.0+20230307.021854.19")
    #extract minor release
    print(cp4d_release)
    minor_release_version = cp4d_release[2:]
    print(minor_release_version)
    dir_path = glob.glob(cp4d_branch +  '/' + cp4d_component + '/' + minor_release_version + '.*.*')
    print("dir_path:", dir_path)
    try:
        cwd = os.chdir(str(dir_path[0]))
    except:
        print("Something wrong with specified\
              directory. Exception- ", sys.exc_info())

    file = tarfile.open('ibm-wsl-6.4.0+20230307.021854.19.tgz')
    file.extractall('.')
    file.close()
    os.chdir("ibm-wsl")
    cwd = os.getcwd()
    print("Inside extracted directory:", cwd)

    os.chdir("inventory/wsl")
    cwd = os.getcwd()
    print("Inside wsl directory:", cwd)

    with open('resources.yaml', 'r') as file:
        configuration = yaml.safe_load(file)

    #print(configuration)
    print(configuration['resources']['resourceDefs']['containerImages'][0]['manifests'][1]['digest'])
    print(len(configuration['resources']['resourceDefs']['containerImages']))


# Parsing of user input from config.yml 
def parse_user_input():
    global cp4d_release
    global cp4d_component
    global cp4d_branch
    with open('config.yml', 'r') as file:
        user_conf = yaml.safe_load(file)

    cp4d_release = user_conf['user_input']['release']
    cp4d_component = user_conf['user_input']['component']
    cp4d_branch = user_conf['user_input']['branch']
    print("User inputs as:", cp4d_release,cp4d_component,cp4d_branch)


# csv to excel conevrsion
def csv_to_excel(csv_file, excel_file):
    csv_data = []
    with open(csv_file) as file_obj:
        reader = csv.reader(file_obj)
        for row in reader:
            csv_data.append(row)
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    for row in csv_data:
        sheet.append(row)
    workbook.save(excel_file)


if __name__ == "__main__":
        parser = argparse.ArgumentParser(prog = 'CP4D Image Scan',  description = 'Scan CP4D images  by various image scanner tool')
        parse_user_input()
        extract_image_and_digest_details()

