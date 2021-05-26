import json
import csv
import requests
import xlsxwriter
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pymongo import MongoClient
from prettytable import PrettyTable


#AbuseIBDB Api Details Collection
url = 'https://api.abuseipdb.com/api/v2/blacklist'

querystring = {
    'confidenceMinimum':'85'
}

headers = {
    'Accept': 'application/json',
    'Key': 'faf9c76f3e886737fe4ddf57758dca511f37e67bc91d8512c958f107cd012af3c7d77225a8f9c440'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)
# Format output
decoded_response = json.loads(response.text)['data']


#writing the response in csv file
with open('data.csv', mode='w', newline='') as data_file:
    data_writer = csv.writer(data_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    data_writer.writerow(['ipAddress', 'countryCode', 'abuseConfidenceScore', 'lastReportedAt'])
    for value in decoded_response:
        data_writer.writerow(
            [value['ipAddress'], value['countryCode'], value['abuseConfidenceScore'], value['lastReportedAt']]
        )


#changing the csv file to xlsx for attachment
workbook = xlsxwriter.Workbook('data1.xlsx')
worksheet = workbook.add_worksheet()
row=0
col=0

for csvRow in decoded_response:
    worksheet.write(row,col,csvRow['ipAddress'])
    worksheet.write(row,col+1,csvRow['countryCode'])
    worksheet.write(row,col+2,csvRow['abuseConfidenceScore'])
    worksheet.write(row,col+3,csvRow['lastReportedAt'])
    row+=1
workbook.close()

#getting api details from virus total for first 20 apis
url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
params = {'apikey':'d65baf97233f01163bab54a3ec6758154a8e65521cdeac1793e9d545463ddead'}
upper_limit = 40
details = []


#reading data from csv file for ip address
with open('data.csv', mode='r') as csv_file:
    data = csv.DictReader(csv_file)
    for index, value in enumerate(data):
        if index > upper_limit-1:
            break

        print('Querying for', value['ipAddress'])
        params['ip'] = value['ipAddress']

        response = requests.get(url, params=params)
        if response.status_code == 200:
            response = json.loads(response.text)
            details.append({
                'country': response['country'] if 'country' in response else None,
                'detected_urls': response['detected_urls'] if 'detected_urls' in response else None,
                'detected_downloaded_samples': response['detected_downloaded_samples'] \
                    if 'detected_downloaded_samples' in response else None,
                'undetected_downloaded_samples': response['undetected_downloaded_samples'] \
                    if 'undetected_downloaded_samples' in response else None,
                'undetected_urls': response['undetected_urls'] if 'undetected_urls' in response else None
            })
        else:
            print(response.status_code, response.json)


# Connecting mongo db server in localhost
try:
    connection = MongoClient()
    connection = MongoClient('localhost', 27017)
    print("MongoDB Connected successfully!!!")

except:  
    print("Could not connect to MongoDB")
  
# database
db = connection.optiv

# Created or Switched to collection names: my_gfg_collection
collection = db.abuseVT
  
# Insert Data
for item in details:
    rec_id1 = collection.insert_one(item)

#querying data
virusTotal = []
for records in collection.find({},{'_id':0}):
    virusTotal.append(records)

#table form to made data
table = PrettyTable(['country', 'detected_urls', 'detected_downloaded_samples','undetected_downloaded_samples','undetected_urls'])
html = """\
        <html>
            <head>
            <style>
                table, th, td {
                    border: 1px solid black;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 5px;
                    text-align: left;    
                }    
            </style>
            </head>
        <body>
        <p>
        Mail Generated For showing virus total results in table<br>
        </p>
        <table>
        <tr>
        <th>Country</th>
        <th>Detected URLs</th>
        <th>Detected URL Samples</th>
        <th>Undetected Download Samples</th>
        <th>Undetected URLs</th>
        </tr>
        <tr>"""

#inserting to table of each record from collection data
for record in virusTotal:
    temp = []
    temp.append(record['country'])
    temp.append(record['detected_urls'])
    temp.append(record['detected_downloaded_samples'])
    temp.append(record['undetected_downloaded_samples'])
    temp.append(record['undetected_urls'])

    html +="<td>"+record['country']+"</td>"
    html +="<td>"+str(record['detected_urls'])+"</td>"
    html +="<td>"+str(record['detected_downloaded_samples'])+"</td>"
    html +="<td>"+str(record['undetected_downloaded_samples'])+"</td>"
    html +="<td>"+str(record['undetected_urls'])+"</td>"
    html+="</tr><tr>"
    table.add_row(temp)
html+="""</tr>
        </table><br>
        <p>
        Please Find the attachment of AbuseIBDB Results<br>
        </p>
        </body>
        </html>
        """

htmlPart = MIMEText(html, 'html')


#The mail addresses and password
sender_address =  input("Enter Sender gmail:")
sender_pass =  input("Enter Gmail Password:")
receiver_address =  input("Enter receiver email:")


#Setup the MIME
message = MIMEMultipart()
message['From'] = sender_address
message['To'] = receiver_address
message['Subject'] = 'Optiv Interview Tasks'
#The subject line

#The body and the attachments for the mail
message.attach(htmlPart)


#sending the csv attachment
attach_file_name = 'data1.xlsx'
fp = open(attach_file_name, "rb")
attachment = MIMEBase('application', 'octate-stream')
attachment.set_payload(fp.read())
fp.close()
encoders.encode_base64(attachment)
attachment.add_header("Content-Disposition", "attachment", filename=attach_file_name)
message.attach(attachment)



#Create SMTP session for sending the mail
session = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
session.starttls() #enable security
session.login(sender_address, sender_pass) #login with mail_id and password
text = message.as_string()
session.sendmail(sender_address, receiver_address, text)
session.quit()
print('Mail Sent')