# -*- coding: utf-8 -*-
import json
import os
import smtplib, ssl
from email.message import EmailMessage
from dotenv import load_dotenv
import snowflake.connector
from snowflake.connector import DictCursor

load_dotenv()

try:
    from openai import OpenAI
except ImportError:
    print("OpenAI module not installed.")
# from pyfaup.faup import Faup


misperrors = {"error": "Error"}
moduleinfo = {'version': '0.1', 'author': 'Ben-David Benyamin',
              'description': 'This Workdlow module will handle the enrichment and analysis of the data to resolve '
                             'what action to take.',
              'module-type': ['action']}
# config fields that your code expects from the site admin
moduleconfig = {
    # Blocking modules break the execution of the current of action
    'blocking': False,
    # Indicates whether parts of the data passed to this module should be filtered. Filtered data can be found under
    # the `filteredItems` key
    'support_filters': True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    'expect_misp_core_format': False,
}


# f = Faup()


def handler(q=False):
    if q is False:
        return False

    cve_list = []
    article_url = ""

    # connecting to snowflakk
    snowflake_connection = snowflake.connector.connect(
        user=os.getenv('SNOWFLAKE_USERNAME'),
        password=os.getenv('SNOWFLAKE_PASSWORD'),
        account='CKLOFJY-CQ58170')

    snowflake_connection.cursor().execute("use client_profiles")
    snowflake_connection.cursor().execute("use warehouse compute_wh")
    company_profile_list = snowflake_connection.cursor().execute("select * from CLIENT_PROFILE").fetchall()


    for attribute in q['Event']['Attribute']:
        # check if the JSON element contains a CVE (vulnerability) or article (Blog URL)
        if attribute["type"] == "vulnerability":
            cve_list.append(attribute["value"])
        elif attribute["comment"] == "Blog URL":
            article_url = attribute["value"]

    # Prompt pieces of the threat level evaluation process
    introduction = """here is an article that addresses a cyber related matter {cti_article}, and here is a list of 
    all the CVEs {cve_list}, evaluate for each company profile there relevance 
    level for both the article and the CVE list\n""".format(cve_list=cve_list, cti_article=article_url)

    request_reply_pattern = """all company profiles will be under each own JSON object, the format of your answer 
    will only be in the following JSON format and with no explaining: { "company profile": { "relevance_score": "total risk score of both the 
    article and CVE list, enter the score as a number from 1 to 10}, "company_UID: "the company UID that is part of the company profile"}"""

    prompt = "{introduction} {clientProfile1} {client_profile2} {format_request}".format(
        introduction=introduction, clientProfile1=company_profile_list[0], client_profile2=company_profile_list[1],
        format_request=request_reply_pattern, request_reply_pattern=request_reply_pattern)

    # Prompt pieces of the enrichment process
    enrichment_introduction = """provide a full executive and technical summary for the following article {cti_article},
     and recovery and remediation steps for each CVE in the following list {cve_list} that the company needs to take in order to protect them self\n""".format(
        cve_list=cve_list, cti_article=article_url)

    enrichment_request_reply_pattern = """the pattern of your answer will be in the same struchture of the following JSON object:
                    {
                        executive summary: here will be the executive summary,
                        technical summary: here will be the technical summary,
                        CVE list: here will be a list of all the CVEs with there recovery and remediation steps
                    }"""

    openai_response_json = json.loads(extract_JSON_string(get_openai_answer(prompt, "gpt-4")))

    #openai_response_json = json.loads('{"company profile 1": {"relevance_score": 2, "company_UID": "7ca3dfdc-524c-4bc7-b00d-db31a2d21379"}, "company profile 2": {"relevance_score": 8, "company_UID": "4f0c9afc-7682-4b77-9f8d-d92875d4f386"}}')

    print(openai_response_json)

    # use this counter to now what company profile has recived each score
    for_loop_counter = 0

    # TODO: create a scoring system that mimics the flowchart that was created (the one that was sent to Guy)
    for company_profile in openai_response_json.items():
        # Creating the enrichment prompt that will have the relevant company profile in each iteration
        snow_con = snowflake_connection.cursor(DictCursor)
        enrichment_prompt = "{enrichment_introduction} {clientProfile} {format_request}".format(
            enrichment_introduction=enrichment_introduction, clientProfile=company_profile_list[for_loop_counter],
            format_request=enrichment_request_reply_pattern)

        if int(company_profile[1]['relevance_score']) >= 7:  # if the relevance score is >= 7
            #company_contact_list = snowflake_connection.cursor().execute("SELECT executive_contact, tecnical_contact FROM CLIENT_PROFILE WHERE company_uid='{company_uid}';".format(company_uid=company_profile[1]['company_UID'])).fetchall()
            company_contact_list = snow_con.execute("SELECT executive_contact, tecnical_contact FROM CLIENT_PROFILE WHERE company_uid='{company_uid}';".format(company_uid=company_profile[1]['company_UID'])).fetchall()
            sendEmail(extract_JSON_string(get_openai_answer(enrichment_prompt, "gpt-4-1106-preview")), company_contact_list)

        elif int(company_profile[1]['relevance_score']) >= 3:  # if the relevance score is >= 3
            get_openai_answer(enrichment_prompt, "gpt-4-1106-preview")

        # keep trace on the current company profile that we are iterating over
        for_loop_counter += 1

    return True


def get_openai_answer(prompt, gpt_model):
    # Set up the OpenAI API client
    client = OpenAI(
        api_key=os.getenv('OPENAI_API_KEY'),  # using environment variable
    )
    # Generate a response ; alternative use n=max_n instead of top_p
    completion = client.chat.completions.create(model=gpt_model,
                                                messages=[{"role": "user", "content": prompt}])
    ai_respons = completion.choices[0].message.content

    return ai_respons


# send the email to the client based on the score
def sendEmail(ai_response_JSON = "hello", contact_list = 0):
    # TODO: process the data to email to the relevant personal and in the right pattern.
    contact_list = [{'EXECUTIVE_CONTACT': '{\n  "email address": "benjaminb@bugsec.com",\n  "full name": " Guy Ruba",\n  "job title": "COO",\n  "phone number": "0521231212"\n}', 'TECNICAL_CONTACT': '{\n  "email address": "bendavidbenyamin@gmail.com",\n  "full name": " Benyamin Ben David",\n  "job title": "CSOC Team Mentor",\n  "phone number": "0521231212"\n}'}]
    message = ai_response_JSON
    smtp_server = "smtp.gmail.com"
    subject = 'executive Summary'
    port = 587  # For starttls
    sender_email = "bendavidbenyamin@gmail.com"
    #receiver_email = "bendavidbenyamin@gmail.com"
    password = os.getenv('GMAIL_EMAIL_PASSWORD')
    the_email = EmailMessage()
    the_email['From'] = sender_email
    the_email['Subject'] = subject
    the_email.set_content(message)

    # Create a secure SSL context
    context = ssl.create_default_context()


    # TODO: iterate each contact and sent the relevant summary to the matching role

    # Iterate through each item in the list
    for item in contact_list:
        # Iterate through each key-value pair in the item
        for key, value in item.items():
            # Parse the inner JSON string
            inner_dict = json.loads(value)

            # Process the inner dictionary as needed
            print(f"Processing {key}:")
            for inner_key, inner_value in inner_dict.items():
                print(f"  {inner_key}: {inner_value}")

    with smtplib.SMTP_SSL(smtp_server, 465, context=context) as smtp:
        smtp.login(sender_email, password)
        for role, contact in contact_list:
            smtp.sendmail(sender_email, contact, the_email.as_string())


def extract_JSON_string(text):
    # Find the first occurrence of '{'
    start_index = text.find('{')
    # Find the last occurrence of '}'
    end_index = text.rfind('}')

    # Extract and return the substring if both characters are found
    if start_index != -1 and end_index != -1:
        return text[start_index:end_index + 1]
    else:
        return "No valid pattern found"


def introspection():
    modulesetup = {}
    try:
        modulesetup['config'] = moduleconfig
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def main():
    file_discriptor = open((r"C:\Users\BenjaminBen-David\Documents\GitHub\my-misp-modules\JSON_testing.txt"),
                         encoding="utf8")
    handler(q=json.loads(file_discriptor.read()))
    file_discriptor.close()


if __name__ == "__main__":
    main()
