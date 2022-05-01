from mailmerge import MailMerge
import xmltodict
import sys
import re

template = sys.argv[1]
filename = sys.argv[2]

xml_file = open(filename, 'rb')
all = xmltodict.parse(xml_file)
all_dict = dict(zip(all['ip']['command'],all['ip']['result']))

document = MailMerge(template)
#print("Fields included in {}: {}".format(template,document.get_merge_fields()))
document.merge(**all_dict)

#ip = str(filename)
#print(type(filename))

document.write(filename + ".docx")