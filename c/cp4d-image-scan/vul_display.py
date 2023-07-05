#import json Python module
import argparse
import json
import csv
import hashlib
import pandas as pd
import openpyxl

# list to maintain all cve detected list
total_cve_list = []

# lists to maintain all cve detected by trivy
trivy_x86_list = []
trivy_power_list = []

# lists to maintain all cve detected by clair
clair_x86_list = []
clair_power_list = []

# lists to maintain all cve detected twistlock
twistlock_x86_list = []
aquasec_x86_list = []

# dictionory to map RHSE and CVE
rhse_cve_dic ={}

# CVE package mapping 
cve_package_dict ={}

# csv conevrsion
csv_header=[ "Sr.No","CVE/RHSE","Trivy(x86)","Trivy(Power)", "Clair(x86)", "Clair(Power)", "Twistlock", "Aquasec"]


# function to parse Aquasec CVE report
def parse_aquasec_cve(path):
    df = pd.read_excel(path, engine='openpyxl',header=None,names=["Format","Resource_Name" ,"Resource_Version","Resource_Path", "Vuln","Severity","NVD_URL","Vendor_URL"  "Publish Dat", "Fix Version", "NVD_Score",   "Vendor_Score"],skiprows=1)
    aquasec_x86_alist = list(df.Vuln)
    for value in aquasec_x86_alist:
        aquasec_x86_list.append(value)
        if not value  in total_cve_list:
            total_cve_list.append(value)


# function to parse Twistlock CVE report
def parse_twistlock_cve(path):
    #df = pd.read_excel(path, engine='openpyxl')
    df = pd.read_excel(path, engine='openpyxl',header=None,names=["CVE","CVSS","Description" ,"Severity","Status","Package_Name","Package_Path","Package_Version","Linki"],skiprows=1)
    twistlock_x86_alist = list(df.CVE)
    for value in twistlock_x86_alist:
        twistlock_x86_list.append(value)
        if not value  in total_cve_list:
            total_cve_list.append(value)


# function to parse Trivy x86 CVE report
def parse_trivy_x86_cve(trivy_x86_json_data):

    trivy_x86_alist = trivy_x86_json_data["Results"]
    for value in trivy_x86_alist:
        for vouValue in value["Vulnerabilities"]:
            if "VendorIDs" in vouValue:
                #print(vouValue["VulnerabilityID"],"==",  vouValue["VendorIDs"])
                trivy_x86_list.append(vouValue["VulnerabilityID"])
                rhse_id = str(vouValue["VendorIDs"])
                rhse_id_str = rhse_id[2:-2]
                rhse_cve_dic[vouValue["VulnerabilityID"]] = rhse_id_str
            else:
                #print(vouValue["VulnerabilityID"])
                trivy_x86_list.append(vouValue["VulnerabilityID"])

            if not vouValue["VulnerabilityID"]  in total_cve_list:
                total_cve_list.append(vouValue["VulnerabilityID"])
                cve_package_dict[str(vouValue["VulnerabilityID"])] = vouValue["PkgName"]
                print(vouValue["VulnerabilityID"])

    return None


# function to parse Trivy power CVE report
def parse_trivy_power_cve(trivy_power_json_data):
    trivy_power_alist = trivy_power_json_data["Results"]
    for value in trivy_power_alist:
        for vouValue in value["Vulnerabilities"]:
            if "VendorIDs" in vouValue:
                #print(vouValue["VulnerabilityID"],"==",  vouValue["VendorIDs"])
                trivy_power_list.append(vouValue["VulnerabilityID"])
                rhse_id = str(vouValue["VendorIDs"])
                rhse_id_str = rhse_id[2:-2]
                rhse_cve_dic[vouValue["VulnerabilityID"]] = rhse_id_str

            else:
                #print(vouValue["VulnerabilityID"])
                trivy_power_list.append(vouValue["VulnerabilityID"])

                
            if not vouValue["VulnerabilityID"]  in total_cve_list:
                total_cve_list.append(vouValue["VulnerabilityID"])
                cve_package_dict[str(vouValue["VulnerabilityID"])] = vouValue["PkgName"]
                print(vouValue["VulnerabilityID"])

    return None


# function to parse clair x86 CVE report
def parse_clair_x86_cve(clair_x86_data):
    #fin = open(clair_x86_data, "rt")
    fin = clair_x86_data
    fout = open("out.txt", "wt")
    for line in fin:
        fout.write(' '.join(line.split()))
        fout.write('\n')
    fin.close()
    fout.close()

    # path of the input and output files
    OutFile = 'File.txt'
    InFile = 'out.txt'
    # holding the line which is already seen
    lines_present = set()
    # opening the output file in write mode to write in it
    The_Output_File = open(OutFile, "w")

    # loop for opening the file in read mode
    for l in open(InFile, "r"):
       # finding the hash value of the current line
          # Before performing the hash, we remove any blank spaces and new lines from the end of the line.
          # Using hashlib library determine the hash value of a line.
          hash_value = hashlib.md5(l.rstrip().encode('utf-8')).hexdigest()
          if hash_value not in lines_present:
             The_Output_File.write(l)
             lines_present.add(hash_value)
    # closing the output text file
    The_Output_File.close()


    with open("File.txt") as fp:
        Lines = fp.readlines()
        for line in Lines:
            b = line.split(" ")
            a = [sub[: -1] for sub in b]
            clair_x86_list.append(a[4])
            if not a[4]  in total_cve_list:
                total_cve_list.append(a[4])
                cve_package_dict[a[4]] = a[2]

            #print(a[4])


    return None


# function to parse clair power CVE report
def parse_clair_power_cve(clair_power_data):
    fin = clair_power_data
    fout = open("out.txt", "wt")
    for line in fin:
        fout.write(' '.join(line.split()))
        fout.write('\n')
    fin.close()
    fout.close()

    # path of the input and output files
    OutFile = 'File.txt'
    InFile = 'out.txt'
    # holding the line which is already seen
    lines_present = set()
    # opening the output file in write mode to write in it
    The_Output_File = open(OutFile, "w")

    # loop for opening the file in read mode
    for l in open(InFile, "r"):
       # finding the hash value of the current line
          # Before performing the hash, we remove any blank spaces and new lines from the end of the line.
          # Using hashlib library determine the hash value of a line.
          hash_value = hashlib.md5(l.rstrip().encode('utf-8')).hexdigest()
          if hash_value not in lines_present:
             The_Output_File.write(l)
             lines_present.add(hash_value)
    # closing the output text file
    The_Output_File.close()


    with open("File.txt") as fp:
        Lines = fp.readlines()
        for line in Lines:
            b = line.split(" ")
            a = [sub[: -1] for sub in b]
            clair_power_list.append(a[4])
            if a[4] not in total_cve_list:
                total_cve_list.append(a[4])
                cve_package_dict[a[4]] = a[2]

            #print(a[4])

    return None


# Funtion to prepare csv report from list
def find_detection_by_tool():
    cve_count = 0
    with open('CVE_detection.csv', 'w') as file_csv:
        writer = csv.writer(file_csv)
        writer.writerow(csv_header)
        for cve in total_cve_list:
            cve_count = cve_count +1
            trivy_x86_d = 'No'
            trivy_power_d = 'No'
            clair_x86_d = 'No'
            clair_power_d = 'No'
            twistlock_d = 'No'
            aquasec_d = 'No'
            if cve in trivy_power_list:
                #print("CVE present in power list too")
                trivy_power_d = 'Yes'
            if cve in trivy_x86_list:
                #print("CVE present in x86 list too")
                trivy_x86_d = 'Yes'
            if cve in clair_power_list:
                #print("CVE present in power list too")
                clair_power_d = 'Yes'
            if cve in clair_x86_list:
                #print("CVE present in x86 list too")
                clair_x86_d = 'Yes'
            if cve in aquasec_x86_list:
                aquasec_d = 'Yes'
            if cve in twistlock_x86_list:
                twistlock_d = 'Yes'
            if cve in rhse_cve_dic.keys():
                if rhse_cve_dic[cve] in trivy_power_list:
                    trivy_power_d = 'Yes'
                if rhse_cve_dic[cve] in trivy_x86_list:
                    trivy_x86_d = 'Yes'
                if rhse_cve_dic[cve] in clair_power_list:
                    clair_power_d = 'Yes'
                if rhse_cve_dic[cve] in clair_x86_list:
                    clair_x86_d = 'Yes'
                if rhse_cve_dic[cve] in twistlock_x86_list:
                    #print("CVE present in x86 list too")
                    twistlock_d = 'Yes'
                    aquasec_d = 'Yes'
                if cve in cve_package_dict:
                    csv_data=[cve_count,cve + " == " + rhse_cve_dic[cve],cve_package_dict[cve],trivy_x86_d,trivy_power_d,clair_x86_d,clair_power_d,twistlock_d,aquasec_d]
                else:    
                    csv_data=[cve_count,cve + " == " + rhse_cve_dic[cve],"Null",trivy_x86_d,trivy_power_d,clair_x86_d,clair_power_d,twistlock_d,aquasec_d]
            else:
                if cve in cve_package_dict:
                    print(cve_package_dict)
                    csv_data=[cve_count,cve + " == " + rhse_cve_dic[cve],cve_package_dict[cve],trivy_x86_d,trivy_power_d,clair_x86_d,clair_power_d,twistlock_d,aquasec_d]
                else:    
                    csv_data=[cve_count,cve + " == " + rhse_cve_dic[cve],"Null",trivy_x86_d,trivy_power_d,clair_x86_d,clair_power_d,twistlock_d,aquasec_d]
            writer.writerow(csv_data)
    return None    


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
	parser = argparse.ArgumentParser(prog = 'CVE Detection',  description = 'Generate readable CVE detection by various image scanner tool')
	parser.add_argument('trivy_x86_file_path', help="File path for trivy x86 image")
	parser.add_argument('trivy_power_file_path', help="File path for trivy power image")
	parser.add_argument('clair_x86_file_path', help="File path for clair x86 image")
	parser.add_argument('clair_power_file_path', help="File path for clair power image")
	parser.add_argument('twistlock_file_path', help="File path for twistlock x86 image")
	parser.add_argument('aquasec_file_path', help="File path for aquasec x86 image")
	parser.add_argument('write_csv', help="Write outputi to CSV")
	args = parser.parse_args()
	with open(args.trivy_x86_file_path) as trivy_x86_file:
		sbom = parse_trivy_x86_cve(json.load(trivy_x86_file))
	with open(args.trivy_power_file_path) as trivy_power_file:
		sbom = parse_trivy_power_cve(json.load(trivy_power_file))
	with open(args.clair_x86_file_path) as clair_x86_file:
		sbom = parse_clair_x86_cve(clair_x86_file)
	with open(args.clair_power_file_path) as clair_power_file:
		sbom = parse_clair_power_cve(clair_power_file)
	parse_aquasec_cve(args.aquasec_file_path)
	parse_twistlock_cve(args.twistlock_file_path)
	find_detection_by_tool()
	csv_to_excel("CVE_detection.csv",args.write_csv+".xlsx")
