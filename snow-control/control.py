from colorama import init as colorama_init
from colorama import Fore, Style
import os
from load import *
import snowflake.connector as snowcon
from queries import SET_SEARCH_PATH
from get_objects import object_scan,filter_objects, save_cache
from plan import plan,print_account_plan
from sqlpriv import gen_queries
from control_state import ControlState
from apply import apply

from styling import *

colorama_init(autoreset=True)




def interactive():
    """
        Entry point into running the CLI in the (default) interactive mode. Reads the text from interactive/
        using formatting as necessary and pausing for user input for
            - connection creds:     acct, username, pwd
            - action:               clear,get,plan,show,apply,exit      (and method seq/conc)
            - roles:                (for plan) roles to plan for
    """
    os.system('clear')

    # Connection Creds
    with open(os.path.join(SCRIPT_DIR, 'interactive/intro.txt'),'r') as f: 
        txt = f.read()
    chunks = txt.split('[break_for_input]')
    account,user,password = [cli_input(chunk.format(**STYLING).strip() + Fore.YELLOW) for chunk in chunks[:-1]]
    account = account if account else os.environ.get('SNOWFLAKE_ACCOUNT')
    organization = os.environ.get('SNOWFLAKE_ORGANIZATION') # TODO: fix
    password = password if password else os.environ.get('SNOWFLAKE_PASSWORD')
    account = f'{organization}-{account}'
    print(chunks[-1])

    if not user:
        print('USER is blank... looking for environment variable SNOWFLAKE_USER')
        user = os.environ['SNOWFLAKE_USER']
    if not password:
        print(f'PASSWORD is blank, starting SSO auth for user {user}')
    
    conn = initialize_connection(account_name = account, username = user, password = password)
    state = ControlState(verbosity = 3)
    state.account, state.connection = account, conn
    state.ignore_objects = get_ignored_object_patterns(state.account)
    
    # MAIN MENU
    os.system('clear')
    while menu_screen(state):
        os.system('clear')
    conn.close()
    exit()

def initialize_connection(account_name:str, username:str, password:str, role:str = 'ACCOUNTADMIN', **kwargs ):
    """
        Open a SF connection to the target account. 
        If password is not provided, SSO verification in an external browser is assumed
        The connection can be customized by kwargs passed.
    """
    assert role.endswith('ADMIN'), 'An admin role is necessary to run this tool (even in a dry run)'
    parameters = {
        'account': account_name,
        'user':username,
        'role':role,
        'session_parameters':{
            'QUERY_TAG':'CONTROL'
        }
    }
    if password:
        parameters['password'] = password
    else:
        print('No password provided, using externalbrowser for SSO auth')
        parameters['authenticator'] = 'externalbrowser'
    
    parameters |= kwargs

    conn = snowcon.connect(**parameters)
    set_environment(conn)
    return conn

def set_environment(conn:snowcon.SnowflakeConnection) -> None:
    """
        Initialize any session variables/run any scripts that need to be run
    """
    cur = conn.cursor()
    cur.execute(SET_SEARCH_PATH)
    cur.close()

def menu_screen(st:ControlState) -> bool:
    print(f'{Style.BRIGHT + Fore.CYAN}ACCOUNT: {Style.RESET_ALL + Fore.YELLOW}{st.account}', end = '\n\n')
    with open(os.path.join(SCRIPT_DIR, 'interactive/menu.txt'),'r') as file:
        txt = file.read()
    inp = cli_input(txt.format(**STYLING) + '\n').lower().strip().split()
    
    # NOTE: this handles bug when people hit enter repeatedly
    if not inp:
        return True
    
    response, *params = inp
    
    method_sequential = ('seq' in params)
    method_concurrent = ('conc' in params)
    print(Style.RESET_ALL,end = '')

    if response == 'clear':
        clear_cache(st.account)
    elif response == 'debug':
        if params and params[0].isnumeric(): 
            debug_level = int(params[0])
            print(f'Setting verbosity level: {debug_level}')
            st.verbosity = debug_level
        else:
            print(f'Improper verbosity level : {debug_level}')
    elif response == 'get':
        print('\n')
        st.print(f'Getting latest list of objects in account {Style.BRIGHT + Fore.YELLOW}{st.account}')
        objects,current_state = object_scan(
            st,
            method = 'seq' if method_sequential else 'conc'
        )
        save_cache(
            st,objects,current_state
        )
    elif response == 'plan':
        roles_string = cli_input('Enter the roles you wish to generate the plan for , separated by a space (default ALL)')
        target_roles = [role.lower().strip() for role in roles_string.split()] if roles_string else None
        plan(
            state = st,
            account = st.account,
            roles_to_plan = target_roles,
            method = 'seq' if method_sequential else 'conc', # default conc,
            plan_users = False if target_roles else True
        )
        print_account_plan(st)
    elif response == 'show':
        print_account_plan(st)
    elif response == 'sql':
        cache_plan = get_plan_from_cache(st.account)
        queries = gen_queries(st.account, cache_plan)
        show(queries)
    elif response == 'apply':
        cache_plan = get_plan_from_cache(st.account)
        executables = [' '.join(q) for q in gen_queries(st.account,cache_plan)]
        apply(
            st,
            plan_id = cache_plan['plan_id'],
            executables = executables,
            method = 'conc' if method_concurrent else 'seq' # default seq
        )
    else:
        return False
    cli_input('\n'*4 + 'To continue press any key')
    return True
    
if __name__ == '__main__':
    interactive()