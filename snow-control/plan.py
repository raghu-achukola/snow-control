from load import (
    load_cache,
    load_role_configuarations,
    write_out_snowplan,
    get_user_roles_from_config,
    get_plan_from_cache, 
    get_unsupported_privs,
    ATOMIC_GROUPS  
)

from sf_object_structures import (
    DETAILED_OBJECT_TYPE_MAPPER,process_name,get_matching,get_futures, pluralize, object_matches_any
)
from get_objects import object_scan
from queries import CURRENT_GRANTS_TO_ROLE, FUTURE_GRANTS_TO_ROLE,GRANTS_TO_USER_QUERY, RETRIEVE_GRANTS_TO_USER_QUERY
from styling import time_func
from control_state import ControlState
import time
from itertools import repeat
from functools import reduce
from typing import Tuple
ALL_OBJECT_TYPES = set(ATOMIC_GROUPS.keys()).union(set(DETAILED_OBJECT_TYPE_MAPPER.values()))
UNSUPPORTED_PRIVS = get_unsupported_privs()


@time_func
def plan(state:ControlState, account, roles_to_plan, from_cache = True, method = 'conc', plan_users = False):
    """
        plan() is the central function that writes out to /{account}/.snowplan
        a detailed plan of how to transform the current access into the target access described in the config file. 

        Steps: 
            1. Obtain the role configs and profiles
            2. Connect to SF
            3. For each role
                a. For each profile granted to each role
                    i. Turn the profile into grants
                    ii. Use venn() to compare the current state with the target state and 
                        get a list of privileges to revoek, those that match up , and those to grant
                    iii. Store in a dictionary
            4. Write out to .snowplan
            5. Close Connection
    """
    PLAN_ID = int(time.time())
    user_configs = get_user_roles_from_config(account=account)
    role_configs, role_profiles = load_role_configuarations(account,roles_to_plan)
    objects,grants = load_cache(account) 
    role_plan, user_plan = {},{}

    if method == 'seq':
        for role, config in role_configs.items():
            role_plan |= plan_single_role(state,objects,grants['roles'],role_profiles,role,config)
        if plan_users:
            for user, config in user_configs.items():
                user_plan |= plan_single_user(state,user,config)
    else:
        role_plans, user_plans = {},{}
        role_plans = state.executor.map(
            plan_single_role,
            repeat(state),repeat(objects),repeat(grants['roles']), repeat(role_profiles),*zip(*role_configs.items())
        )
        if plan_users:
            user_plans = state.executor.map(
                plan_single_user,
                repeat(state),
                *zip(*user_configs.items())
            )
        role_plan  = reduce(lambda x,y: x|y, role_plans)
        user_plan = reduce(lambda x,y: x|y, user_plans, {})
    write_out_snowplan(account,role_plan,user_plan,plan_id = PLAN_ID)
    # log_snowplan(state,account)

def plan_single_role(state:ControlState, objects,role_grants,profiles,role,role_config):
    state.print(f'Planning single role: {role}', verbosity_level=3)
    target_state_grants = set()
    associated_profiles = role_config['profiles']


    for assoc_prof in associated_profiles:
        for profile_name, profile_parameters in assoc_prof.items():
            profile_config = profiles[profile_name]
            target_state_grants |= profile_to_grants(state,objects,profile_name,profile_config,**profile_parameters)
    current_state_grants = role_grants.get(role.upper(), {})
    revoke,ok,grant = venn(current_state_grants,target_state_grants)
    return {
        role: {
            'to_revoke':revoke,
            'ok':ok,
            'to_grant':grant
        }
    }

def plan_single_user(state:ControlState, user:str, target_state:set):
    current_state = get_current_users_roles(state,user)
    to_revoke, ok, to_grant = venn(current_state,target_state)
    return {
        user:{
            'to_revoke': [ ['USAGE ','ROLE', role] for role in to_revoke],
            'ok': [ ['USAGE','ROLE',role] for role in ok ],
            'to_grant':[ ['USAGE','ROLE',role] for role in to_grant]
        }
    }
def profile_to_grants(state:ControlState,all_objects:dict,profile_name:str, profile:dict, **requires) -> set: 
    """
        This function converts a role profile (
            a collection of atomic groups on objects matching regex patterns
        ) to a list of atomic privileges
    """
    param_string = [f'{k}={repr(v)}' for k,v in requires.items()]
    state.print(f"Beginning conversion of profile {profile_name}({','.join(param_string)})", verbosity_level=5)
    grants = []
    future_grants = []
    for object_type, object_privs in profile['privileges'].items():
        generic_object_type = DETAILED_OBJECT_TYPE_MAPPER.get(object_type,object_type)
        if object_type == 'role':
            continue
        elif object_type == 'account':
            grants += gen_acct_level_grants(object_privs)
            continue
        for priv,objects in object_privs.items():
            formatted = [obj.format(**requires).upper() + '$' for obj in objects]
            matched_objects = get_matching(all_objects,object_type,formatted)
            futures = get_futures(
                all_objects,
                object_type,
                [
                    obj[:-2].rstrip('[.]').format(**requires).upper() + '$' # don't use strip() bc multiple
                    for obj in objects if obj.endswith('.*')
                ]
            )

            grants += [
                (atomic_priv.upper(),generic_object_type.upper(),matched_object.upper())
                for atomic_priv in ATOMIC_GROUPS[object_type][priv]
                for matched_object in matched_objects
            ]
            target_future = f"FUTURE {pluralize(generic_object_type).upper()} IN {'DATABASE' if object_type.lower() == 'schema' else 'SCHEMA'}"
            future_grants += [
                (atomic_priv.upper(),target_future,f.upper())
                for atomic_priv in ATOMIC_GROUPS[object_type][priv]
                for f in futures
            ]
    return {grant for grant in set(grants) | set(future_grants) if (grant[0],grant[1]) not in UNSUPPORTED_PRIVS}

def gen_acct_level_grants(account_privilege_profile:dict) -> str: 
    '''
        account_privilege_profile:{
            see_all_objects: <acctname>
        }
    '''
    return [
        (atomic_priv.upper(),'ACCOUNT',acct.upper())
        for atomic_group,acct in account_privilege_profile.items()
        for atomic_priv in ATOMIC_GROUPS['account'][atomic_group]
    ]


def venn(set1:set, set2:set) -> Tuple[set,set,set]:
    """
        Creates a venn diagram between two sets: 
        (   Set 1     (  I  )    Set 2   )
    """
    return set1-set2, set1.intersection(set2), set2-set1



def get_current_users_roles(state:ControlState,user:str)-> set:
    cur = state.connection.cursor()
    state.print(f'Executing show query on user {user}', verbosity_level = 4)
    query = GRANTS_TO_USER_QUERY.format(user=user)
    cur.execute(query)
    qid = cur.sfqid
    state.print(f'Retrieving current grants to user {user}', verbosity_level = 3)
    roles_granted = set(x for x, in cur.execute(RETRIEVE_GRANTS_TO_USER_QUERY.format(qid =qid)).fetchall())
    return roles_granted

    
def log_snowplan(state,account):
    pass

def print_account_plan(state:ControlState) -> None:
    plan = get_plan_from_cache(account = state.account)
    role_plan = plan['ROLES']
    user_plan = plan['USERS']
    state.print_formatted_plan(role_plan,grants_to = 'ROLE')
    state.print_formatted_plan(user_plan,grants_to = 'USER')
