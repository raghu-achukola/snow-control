import os
import yaml
import json 
import pandas as pd 
from colorama import Style, Fore 
from typing import Tuple




SCRIPT_DIR = os.path.dirname(__file__)
CONFIG_DIR = os.environ.get('CONTROL_CONFIG_DIR',SCRIPT_DIR)

with open(os.path.join(CONFIG_DIR, 'config/atomic_groups.yaml'), 'r') as file:
    ATOMIC_GROUPS  = yaml.safe_load(file)
with open(os.path.join(SCRIPT_DIR,'interactive/intro.txt'),'r') as file: 
    CLI_INTRO_TEXT = file.read()
with open(os.path.join(SCRIPT_DIR,'interactive/menu.txt'),'r') as file: 
    CLI_MENU_TEXT = file.read()

def clear_cache(account_name:str, files_to_clear = ['.snowcache','.snowplan','.snowplansql']):
    for file in files_to_clear: 
        open(os.path.join(CONFIG_DIR,f'config/{account_name}/{file}'),'w').close()


def load_cache(account:str):
    with open(os.path.join(CONFIG_DIR,f'config/{account}/.snowcache'),'r') as f: 
        retrieved = json.loads(f.read())
        print(f"Retrieving cached record of objects from {Style.BRIGHT + Fore.YELLOW} {retrieved['local_cached_time']} {Style.RESET_ALL} local_time")
        return retrieved['objects'], {
           'roles': {role: set(role_grants) for role, role_grants in retrieved['current_state']['roles'].items()},
           'users': {user: set(user_grants) for user, user_grants in retrieved['current_state']['users'].items()}
        }
    

def get_plan_from_cache(account:str): 
    return json.loads(open(os.path.join(CONFIG_DIR,f'config/{account}/.snowplan'),'r').read())

def get_user_roles_from_config(account:str): 
    return {
        user: set(roles)
        for user, roles in 
        yaml.safe_load(open(os.path.join(CONFIG_DIR,f'config/{account}/user_profiles.yaml'),'r')).items()
    }

def load_role_configuarations(account_name:str, target_roles:list = None) -> Tuple[dict,dict]:
    """
        Retrieves account specific role configuration from config files. 
        Optional filter for the configs to only contain the roles in target_roles
    """
    with open(os.path.join(CONFIG_DIR,f'config/{account_name}/roles.yaml'),'r') as f:
        role_configs = yaml.safe_load(f)
    with open(os.path.join(CONFIG_DIR,f'config/{account_name}/role_profiles.yaml'),'r') as f:
        role_profiles = yaml.safe_load(f)
    filtered_role_configs = {role:role_configs[role] for role in target_roles} if target_roles else role_configs

    return filtered_role_configs,role_profiles


def write_out_snowplan(account:str, role_snowplan:dict, user_snowplan:dict = {}, plan_id:int = -1):
    with open(os.path.join(CONFIG_DIR,f'config/{account}/.snowplan'),'w') as f:
        f.write(
            json.dumps(
                {
                    'plan_id':plan_id,
                    'ROLES':{
                        role:{
                            delta_type: list(delta)
                            for delta_type,delta in plan_for_role.items()
                        }
                        for role, plan_for_role in role_snowplan.items()
                    },
                    'USERS':{
                        user:{
                            delta_type:list(delta)
                            for delta_type,delta in plan_for_user.items()
                        }
                        for user, plan_for_user in user_snowplan.items()
                    }
                }
                ,indent = 2
            )
        )

def get_unsupported_privs():
    with open(os.path.join(SCRIPT_DIR,'ignore','privs.yaml')) as f: 
        unsupported_privs = [
            (priv.upper(), target_type.upper())
            for priv,target_type in yaml.safe_load(f).items()
            for target_type in target_type
        ]
    return unsupported_privs

def get_ignored_object_patterns(account:str):
    with open(os.path.join(CONFIG_DIR,'config',account,'ignore','objects.yaml')) as f: 
        PATTERNS = [f"^{pattern.upper()}$" for pattern in yaml.safe_load(f)['full_name_patterns']]
    return PATTERNS


def write_out_sql_snowplan(account:str, executables:list):
    with open(os.path.join(CONFIG_DIR,f'config/{account}/.snowplansql'),'w') as f:
        f.write(
            ';\n'.join(executables)
        )
