import re 
import pandas as pd 
from typing import Iterable



DETAILED_OBJECT_TYPE_MAPPER = {
    'materialized view': 'view',
    'external table': 'table',
    'internal stage': 'stage',
    'external stage': 'stage',
    'storage integration': 'integration',
    'api integration': 'integration',
    'notification integration': 'integration'
}

ALOs = ['warehouse','database','storage integration','notification integration','api integration']
ALO_FULL_NAME = ['name']
NLOs = ['table','dynamic table','view','stage','pipe','task','stream',
        'tag',
        'file format']
FNCs = ['procedure','function']
NLO_FULL_NAME = ['database_name','schema_name','name']
FNC_FULL_NAME = ['catalog_name','schema_name','arguments']


GET_FULL_NAME = {alo:ALO_FULL_NAME for alo in ALOs} | {'schema':['database_name','name']} | {nlo:NLO_FULL_NAME for nlo in NLOs} | {fnc:FNC_FULL_NAME for fnc in FNCs}



def process_name(name:str, obj_type:str) -> str:
    """
        Snowflake has an extremely irregular way of standardizing the fully qualified name for functions (esp external functions)
        and proceudres. This is a problem as it results in obejcts not having a clear id/join condition to be compared. 
        This function attempts to standardize a sproc/function definition to be : 

        db_name.schema.function_name(arg_type,arg_type,...)

        from variations like 
        db_name.schema."function_name(arg_type,...):return_type"
        db_name.schema.function_name
        db_name.schema."function_name(arg_name arg_type, ...)"
        db_name.schema."function_name(arg_name arg_type, ...):return_type"
    """
    if obj_type not in ('FUNCTION','PROCEDURE'):
        return name
    local_name_pattern = r'.*[.].*[.](.*[(].*[)][:].*)'
    reg_match = re.match(local_name_pattern,name)

    assert reg_match
    main_name = reg_match.groups(1)[0].split(':')[0].replace('"','')
    arg_pattern = r'.*[(](.*)[)]'
    arg_match = re.match(arg_pattern, main_name)
    assert arg_match
    signature = arg_match.groups(1)[0]
    if signature: 
        args = [x.strip().split()[-1] for x in signature.split(',')]
        main_name = main_name.replace(signature, f"{','.join(args)}")
    return name.replace(reg_match.groups(1)[0],main_name)

def get_matching(objects:dict[str,dict], object_type:str, patterns:Iterable[str])-> set: 
    """
        Find all objects of type {object_type} in the Snowflake account matching {patterns} 
        a list of regex patterns
    """
    # Snowflake object names are not unique unless they are fully qualified
    # unfortunately... that query is a little different for each object type

    matches = set()

    # Snowflake only recognizes "Stages" as an object type....
    # but internal stages have different privileges than external stages
    generalized_object_type = 'stage' if object_type.endswith('stage') else object_type
    generalized_object_type = 'integration' if object_type.endswith('integration') else generalized_object_type

    dictionary = objects[object_type]
    # Construct the filter clause for the regex match: the constructed full name
    # must match one of the patterns in the atomic group. As such: 
    #
    # re.match('{pattern_1}', ful_name)
    # or
    # re.match('{pattern_2}',full_name)
    # or
    # .
    # .
    # .
    # re.match('{pattern_n}', full_name)
    regexp_match = lambda name: object_matches_any(name,patterns)
    matched = {k:v for k,v in dictionary.items() if regexp_match(k) and v.get('schema_name','')!= 'INFORMATION_SCHEMA'}
    if len(matched): 
        matches |= set(matched)
    return matches

def object_matches_any(name:str,patterns:list):
    return any([re.match(pattern,name, re.IGNORECASE) for pattern in patterns]) 

def get_futures(objects:dict[str,dict],object_type:str,patterns:Iterable[str]):
    regexp_match = lambda name: any([re.match(pattern,name) for pattern in patterns])
    if object_type.lower() != 'schema':
        spec_objects = objects['schema'].copy()
        spec_objects = {k:v for k,v in spec_objects.items() if v.get('name','') != 'INFORMATION_SCHEMA'}
    else:
        spec_objects = objects['database'].copy()
        spec_objects = {k:v for k,v in spec_objects.items() if k != 'SNOWFLAKE'}
    spec_objects = {k:v for k,v in spec_objects.items() if regexp_match(k)}
    return set(spec_objects)

def pluralize(word:str):
    if word: 
        if word[-1] == 'Y':
            return word[:-1] + 'IES'
        return word + 'ES' if word[-1] in ('S','Z','X') or word[-2:] in ('SH','CH') else word + 'S'
    return ''