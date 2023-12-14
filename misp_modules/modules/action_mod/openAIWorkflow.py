# -*- coding: utf-8 -*-

import json
from pyfaup.faup import Faup

try:
    from openai import OpenAI
except ImportError:
    print("OpenAI module not installed.")

misperrors = {"error": "Error"}

moduleinfo = {'version': '0.1', 'author': 'Ben-David Benjamin',
              'description': 'This Workdlow module will handle the enrichment and analysis of the data to resolve '
                             'what action to take.',
              'module-type': ['action']}

# config fields that your code expects from the site admin
moduleconfig = {
    'params': {
        'article_content': {
            'type': 'string',
            'description': 'The content of the article that needs to be checked for relevance for any client',
            'value': 'Qbot attacks are in the rise for EU based companies',
        },
    },
    # Blocking modules break the exection of the current of action
    'blocking': False,
    # Indicates whether parts of the data passed to this module should be filtered. Filtered data can be found under the `filteredItems` key
    'support_filters': True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    'expect_misp_core_format': False,
}


f = Faup()

def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)


    introduction = ("hello, the following link contains an article related to the cyber landscape, ")
    base_prompt_1 = ("I am a mid-size bank located in Belgium, I am using both Linux and Windows systems, and have "
                     "an active .NET environment in my organization, please tell me from 1 to 10 what is the level of "
                     "relevance of this article to me.")
    article_url = "https://blog.sekoia.io/customerloader-a-new-malware-distributing-a-wide-variety-of-payloads/"

    base_prompt_3 = ("please answer me in JSON format and put the part where you "
                     "address the relevance of this article to my organization in a different Key:value pair, "
                     "answer only in the format like 'the relevance score is X out of Y'")

    prompt = "{base_prompt_1} {article_url} {format_request}".format(
        base_prompt_1=introduction, article_url=article_url, format_request=base_prompt_3)

    get_openai_answer(prompt,)

    #return {"results": [{"types": mispattributes["output"],
    #                     "values": [get_openai_answer(prompt, request["config"].get("api_key"))]}]}
    return True


def get_openai_answer(prompt):
    # Set up the OpenAI API client
    client = OpenAI(
        api_key="",  # this is also the default, it can be omitted
    )

    # Generate a response ; alternative use n=max_n instead of top_p
    completion = client.chat.completions.create(model="gpt-3.5-turbo",
                                                messages=[{"role": "user", "content": prompt}])
    ai_respons = completion.choices[0].message.content

    return ai_respons


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
