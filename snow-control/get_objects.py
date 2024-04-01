from queries import * 
from styling import time_func
from sf_object_structures import * 
from load import * 
import snowflake.connector as snowcon
from typing import Tuple
from concurrent.futures import ThreadPoolExecutor
import json 
from time import localtime,strftime
from control_state import ControlState
from itertools import repeat


@time_func
def object_scan(state:ControlState, method = 'conc') -> dict:
    objects = {}
    conn = state.connection
    tp_executor = state.executor
    def individual_object_scan(item: Tuple[str,list[str]]):
        obj_type, key = item
        cur = conn.cursor()
        formatted_query = (INTEGRATION_SHOW_QUERY if obj_type.upper().endswith('INTEGRATION') else SHOW_QUERY).format(obj_type)
        state.print(f'Executing show query on object type {obj_type}', verbosity_level=4)
        cur.execute(formatted_query)
        qid = cur.sfqid
        state.print(f'Retrieving objects of type {obj_type} in account', verbosity_level=3)
        panda = cur.execute(
            NAME_QUERY.format(
                qid = qid, 
                key = ','.join([f'"{s}"' for s in key])
            )
        ).fetch_pandas_all()

        if obj_type.upper() in ('PROCEDURE','FUNCTION'):
            panda = panda[panda['is_builtin'] == 'N']
        panda['FULL_NAME'] = panda['FULL_NAME'].apply(
            lambda x: process_name(x.replace(' RETURN ',':'), obj_type.upper())
        )
        panda = panda[panda['FULL_NAME'].apply(lambda name: not object_matches_any(name,state.ignore_objects))]
        
        return (obj_type,list(panda.itertuples()))

    if method == 'seq':
        for obj_type,full_name_columns in GET_FULL_NAME.items():
            print(obj_type)
            print(full_name_columns)
            _, result_df = individual_object_scan((obj_type,full_name_columns))
            objects[obj_type] = result_df
    else: 
        results = tp_executor.map(individual_object_scan,GET_FULL_NAME.items())
        for obj_type,result_df in results:
            objects[obj_type] = result_df

    return objects

def filter_objects(state:ControlState, objects:dict[str,pd.DataFrame], method:str) -> dict[str,list]:
    dbs = objects['database']
    # Shared Databases
    objects['shared database'] =  filter(lambda row: row.kind == 'IMPORTED DATABASE', dbs)
    # Application DBs
    objects['application database'] = filter(lambda row: row.kind == 'APPLICATION' , dbs)
    shared_dbs = set([row.name for row in objects['shared database']])
    application_dbs = set([row.name for row in objects['application database']])
    ignore_dbs = shared_dbs | application_dbs

    # Special Consideration Stage
    objects['internal stage'] = filter(lambda row: row.type == 'INTERNAL' , objects['stage'])
    objects['external stage'] = filter(lambda row: row.type == 'EXTERNAL' , objects['stage'])

    # Special Consideration: Information Schema Views
    objects['view'] = filter(lambda row: row.schema != 'INFORMATION_SCHEMA' , objects['view'])
    # Special Consideration: View
    objects['materialized view'] = filter(lambda row: row.is_materialized == 'true' , objects['view'])
    objects['view'] = filter(lambda row: row.is_materialized == 'false' , objects['view'])


    # Special Consideration: xtab
    objects['external table'] =  filter(lambda row: row.is_external == 'Y' , objects['table'])
    objects['table'] = filter(lambda row: row.is_external == 'N' , objects['table'])

    # Special Consideration: Objects where db/container is a shared/app db
    if method == 'seq':
        return dict(
            filter_function(obj_typ,object_rows,ignore_dbs)
            for obj_typ, object_rows in objects.items() 
        )
    else:
        return { 
            sf_type:df 
            for sf_type,df in  
            state.executor.map(
                filter_function,
                *zip(*objects.items()),repeat(ignore_dbs)
            )
        }


def filter_function(obj_type:str, obj_rows:list, ignore_dbs:set, ignore_pattern =  r'.*_(DEV|QA|PROD)_[0-9]{1,5}') -> Tuple[str,pd.DataFrame]:
    identifier = 'database_name'
    if obj_type.lower() in FNCs:
        identifier = 'catalog_name'
    elif obj_type.lower() == 'database':
        identifier = 'name'
    elif obj_type.lower() in ALOs or obj_type.lower() in ('shared database','application database'):
        identifier = None
    
    if identifier:
        filter_fn = lambda row: getattr(row,identifier) not in ignore_dbs and not re.match(ignore_pattern,getattr(row,identifier))
        return obj_type,filter(filter_fn, obj_rows)
    return obj_type,obj_rows
    

def save_cache(st:ControlState, objects:dict[str,pd.DataFrame]):
    with open(os.path.join(CONFIG_DIR,'config',st.account,'.snowcache'),'w') as f:

        f.write(json.dumps(
            {
               'local_cached_time': strftime("%Y-%m-%d %H:%M:%S",localtime()),
               'objects':{
                   obj_typ:{row.FULL_NAME: row for row in rows}
                   for obj_typ,rows in objects.items()
               }
            }, indent = 4
        )
        )