# -*- coding: utf-8 -*-

import json
try:
    from openai import OpenAI
except ImportError:
    print("OpenAI module not installed.")


misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "ip-src", "ip-dst", "url"], "output": ["text"]}
moduleinfo = {"version": "0.1", "author": "Koen Van Impe",
              "description": "Query OpenAI. Used for demo purposes. Take into account the sharing and sensitivity level of the data you share with OpenAI!",
              "module-type": ["action"]}


moduleconfig = {
    'params': {
        'mattermost_hostname': {
            'type': 'string',
            'description': 'The Mattermost domain or URL',
            'value': 'example.mattermost.com',
        },
        'bot_access_token': {
            'type': 'string',
            'description': 'Access token generated when you created the bot account',
        },
        'channel_id': {
            'type': 'string',
            'description': 'The channel you added the bot to',
        },
        'message_template': {
            'type': 'large_string',
            'description': 'The template to be used to generate the message to be posted',
            'value': 'The **template** will be rendered using *Jinja2*!',
        },
    },
    # Blocking modules break the exection of the current of action
    'blocking': False,
    # Indicates whether parts of the data passed to this module should be filtered. Filtered data can be found under the `filteredItems` key
    'support_filters': True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    'expect_misp_core_format': False,
    'api_key': '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'
}


# returns either "boolean" or "data"
# Boolean is used to simply signal that the execution has finished.
# For blocking modules the actual boolean value determines whether we break execution
returns = 'boolean'
misperrors = {'error': 'Error'}

# config fields that your code expects from the site admin
moduleconfig = {
    'params': {
        'mattermost_hostname': {
            'type': 'string',
            'description': 'The Mattermost domain or URL',
            'value': 'example.mattermost.com',
        },
        'bot_access_token': {
            'type': 'string',
            'description': 'Access token generated when you created the bot account',
        },
        'channel_id': {
            'type': 'string',
            'description': 'The channel you added the bot to',
        },
        'message_template': {
            'type': 'large_string',
            'description': 'The template to be used to generate the message to be posted',
            'value': 'The **template** will be rendered using *Jinja2*!',
        },
    },
    # Blocking modules break the exection of the current of action
    'blocking': False,
    # Indicates whether parts of the data passed to this module should be filtered. Filtered data can be found under the `filteredItems` key
    'support_filters': True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    'expect_misp_core_format': False,
}


# returns either "boolean" or "data"
# Boolean is used to simply signal that the execution has finished.
# For blocking modules the actual boolean value determines whether we break execution
returns = 'boolean'

moduleinfo = {'version': '0.1', 'author': 'Sami Mokaddem',
              'description': 'Simplistic module to send message to a Mattermost channel.',
              'module-type': ['action']}

f = Faup()
def handler(q=False):
    if q is False:
        return False


    request = json.loads(q)
    if request.get("domain"):
        attribute_type = "domain"
        attribute_value = request["domain"]
    elif request.get("hostname"):
        attribute_type = "domain"
        attribute_value = request["domain"]
    elif request.get("url"):
        attribute_type = "URL"
        attribute_value = request["url"]
    elif request.get("ip-src"):
        attribute_type = "IP address"
        attribute_value = request["ip-src"]
    elif request.get("ip-dst"):
        attribute_type = "IP address"
        attribute_value = request["ip-dst"]
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    if not request.get("config") or not request["config"].get("api_key"):
        misperrors["error"] = "API key is missing"
        return misperrors

    base_prompt_1 = "I'm a cyber threat analyst. First I need you to give me a short report about what I have to do with the malicious"
    base_prompt_2 = "and what actions IT administrators should take to prevent traffic to this"
    base_prompt_3 = "Then I want you to add a separator with 'Related Activity'. Then  I want you to list all know threat actors that are using this"
    base_prompt_4 = "in their camaigns and operations."
    prompt = "{base_prompt_1} {attribute_type} {attribute} {base_prompt_2} {attribute_type}. {base_prompt_3} {attribute_type} {base_prompt_4}".format(base_prompt_1=base_prompt_1, attribute=attribute_value, attribute_type=attribute_type, base_prompt_2=base_prompt_2, base_prompt_3=base_prompt_3, base_prompt_4=base_prompt_4)

    return {"results": [{"types": mispattributes["output"],
                      "values": [get_openai_answer(prompt, request["config"].get("api_key"))]}]}


def get_openai_answer(prompt, request_api_key):

    # Set up the OpenAI API client
    client = OpenAI(
        api_key=request_api_key,  # this is also the default, it can be omitted
    )

    # Generate a response ; alternative use n=max_n instead of top_p
    completion = client.chat.completions.create(model="gpt-3.5-turbo",
                                                      messages=[{"role": "user", "content": prompt}])
    ai_respons = completion.choices[0].message.content

    return ai_respons


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo