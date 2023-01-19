import os
import hashlib
import email
import re
from email import policy
from email.parser import BytesParser
import os
import configparser
import sqlite3

def extract_eml_elements(file_path):
    with open(file_path, 'rb') as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    # Extract basic email elements
    from_address = msg['from']
    to_address = msg['to']
    cc_address = msg['cc']
    bcc_address = msg['bcc']
    subject = msg['subject']
    sent_date = msg['date']
    message_id = msg['message-id']
    body = msg.get_body(preferencelist=('plain', 'html')).get_content()

    # Check for SPF, DMARC, and DKIM
    spf_enabled = False
    dmarc_enabled = False
    dkim_enabled = False
    for header in msg._headers:
        if header[0].lower() == 'authentication-results':
            if 'spf=pass' in header[1]:
                spf_enabled = True
            if 'dmarc=pass' in header[1]:
                dmarc_enabled = True
            if 'dkim=pass' in header[1]:
                dkim_enabled = True

    # Extract URLs from body
    urls = re.findall(r'(https?://\S+)', body)

    # Extract attachments and calculate SHA256 hash
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue

        # Save attachment to attachments folder and calculate SHA256 hash
        attachment_path = os.path.join('attachments', part.get_filename())
        with open(attachment_path, 'wb') as fp:
            fp.write(part.get_payload(decode=True))
        sha256_hash = hashlib.sha256(open(attachment_path, 'rb').read()).hexdigest()

        attachments.append({'name': part.get_filename(), 'hash': sha256_hash, 'path': attachment_path})

    # Return extracted elements
    return {
        'from': from_address,
        'to': to_address,
        'cc': cc_address,
        'bcc': bcc_address,
        'subject': subject,
        'sent_date': sent_date,
        'message_id': message_id,
        'body': body,
        'spf_enabled': spf_enabled,
        'dmarc_enabled': dmarc_enabled,
        'dkim_enabled': dkim_enabled,
        'urls': urls,
        'attachments': attachments
    }


def save_to_database(eml_elements):
    # Connect to database
    conn = sqlite3.connect('email_data.db')
    c = conn.cursor()

    # Create table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS emails
                 (from_address TEXT, to_address TEXT, cc_address TEXT, bcc_address TEXT, 
                 subject TEXT, sent_date TEXT, message_id TEXT, body TEXT,
                 spf_enabled BOOLEAN, dmarc_enabled BOOLEAN, dkim_enabled BOOLEAN)''')

    # Insert email elements into table
    c.execute("INSERT INTO emails VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
        eml_elements['from'], eml_elements['to'], eml_elements['cc'], eml_elements['bcc'],
        eml_elements['subject'], eml_elements['sent_date'], eml_elements['message_id'], eml_elements['body'],
        eml_elements['spf_enabled'], eml_elements['dmarc_enabled'], eml_elements['dkim_enabled']
    ))

    # Create table for attachments if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS attachments
                 (email_id INTEGER, name TEXT, hash TEXT, path TEXT)''')

    # Get ID of last inserted email
    c.execute("SELECT last_insert_rowid()")
    email_id = c.fetchone()[0]

    # Insert attachments into attachments table
    for attachment in eml_elements['attachments']:
        c.execute("INSERT INTO attachments VALUES (?, ?, ?, ?)", (
            email_id, attachment['name'], attachment['hash'], attachment['path']
        ))

    # Commit changes and close connection
    conn.commit()
    conn.close()


def main():
    # Read configuration file
    # config.ini shuld be formatted
    # [DEFAULT]
    # source = /path/to/file_or_directory 

    config = configparser.ConfigParser()
    config.read('config.ini')
    source = config.get('DEFAULT', 'source')
    
    # Check if source is a file or a directory
    if os.path.isfile(source):
        process_file(source)
    elif os.path.isdir(source):
        process_directory(source)
    else:
        print("Invalid source specified in config.ini")

def process_file(file_path):
    eml_elements = extract_eml_elements(file_path)
    save_to_database(eml_elements)
    print("Processed file:", file_path)

def process_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.eml') or file.endswith('.msg'):
                file_path = os.path.join(root, file)
                process_file(file_path)

if __name__ == "__main__":
    main()


                
