# TODO: some imports might be redundant 
import requests
import jsons
from xml.dom import minidom
import sys
# import getopt
import logging
from datetime import datetime
from pytz import timezone
import pytz
from pathlib import Path
import time
import json
from jproperties import Properties

alert_list = []
projects_dict = {}
headers = {}
configs = Properties()   
script_report = {}

# MAKE SURE YOU ADD AN ENTRY FOR "type": "issue" or "type": "metric".
ISSUE_ALERTS = {
    "An Unassigned Error Is Occurring": jsons.dumps({
        "actionMatch":"all",
        "filterMatch":"all",
        "actions":[],
        "conditions":[
            {"id":"sentry.rules.conditions.first_seen_event.FirstSeenEventCondition"},
            {"interval":"1h","id":"sentry.rules.conditions.event_frequency.EventFrequencyCondition","comparisonType":"count","value":"100"},
            {"interval":"1h","id":"sentry.rules.conditions.event_frequency.EventUniqueUserFrequencyCondition","comparisonType":"count","value":"100"}
        ],
        "filters":[
            {"targetType":"Unassigned","id":"sentry.rules.filters.assigned_to.AssignedToFilter"}
        ],
        "frequency":"10",
        "type":"issue" # used by this script, not Sentry API, to determine which alert-creation endpoint to use
    }),
    "Regression Error Occurred": jsons.dumps({
      "actionMatch":"all",
      "filterMatch":"all",
      "actions":[],
      "conditions":[
        {"id":"sentry.rules.conditions.regression_event.RegressionEventCondition"}
       ],
       "filters":[
         {"id":"sentry.rules.filters.latest_release.LatestReleaseFilter"}
       ],
       "frequency":"5",
       "type": "issue" # used by this script, not Sentry API, to determine which alert-creation endpoint to use
    }),
    "Users Experiencing Error Frequently": jsons.dumps({
        "actionMatch":"all",
        "filterMatch":"all",
        "actions":[],
        "conditions": [
            {
                "interval":"5m",
                "id":"sentry.rules.conditions.event_frequency.EventUniqueUserFrequencyCondition",
                "comparisonType":"count",
                "value":"20"
            }
        ],
        "filters":[],
        "frequency":"5",
        "type": "issue"
    }),
    "Error Matches Tag <todo: set tag rule>": jsons.dumps({
            "actionMatch":"all",
            "filterMatch":"all",
            "actions":[],
            "conditions":[
                {
                    "interval":"5m",
                    "id":"sentry.rules.conditions.event_frequency.EventUniqueUserFrequencyCondition",
                    "comparisonType":"count",
                    "value":"50"
                }
            ],
            "filters":[
                {
                    "match":"co",
                    "id":"sentry.rules.filters.tagged_event.TaggedEventFilter",
                    "key":"exampleKey",
                    "value":"exampleValue"
                }
            ],
            "frequency":30,
            "type":"issue"
        })

}

def do_setup():
    global configs
    global headers
    global current_datetime
    required_config_keys = ["ORG_NAME", "AUTH_KEY", "CRITICAL", "WARNING", "SLEEP_TIME", "ALERT_RULE_SUFFIX"]
    try:
        # Init logger
        current_datetime = datetime.now().strftime('%m-%d-%Y_%I:%M:%S %Z')
        logging.basicConfig(filename=f'alert_logfile_{current_datetime}.log', format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %I:%M:%S')
        logging.getLogger().setLevel(logging.ERROR)
        logging.getLogger().setLevel(logging.INFO)

        # Read configuration
        with open('config.properties', 'rb') as config_file:
            configs.load(config_file)

        keys = configs.__dict__
        keys = keys['_key_order']
       
        diff = [i for i in required_config_keys + keys if i not in required_config_keys or i not in keys]
        result = len(diff) == 0
        if not result:
            logging.error(f'These config {len(diff)} key(s) are missing from config file: {diff[:5]}')
            sys.exit()

        for item in required_config_keys:
            if item not in keys:
                print(item)
                logging.error(item + ' is a missing key in your config file.')
                logging.error()
                
      
        for key, value in configs.items():
            if(value.data == ''):
                logging.error('Value for ' + key + ' is missing.')
                sys.exit()

        # Init request headers
        headers = {'Authorization': "Bearer " + configs.get("AUTH_KEY").data, 'Content-Type' : 'application/json'}
    except Exception as e: 
        print(f'do_setup: failed to setup - {e}')
        sys.exit()

    
def get_alerts(): 
    global alert_list
    global configs
    global headers
    try: 
        response = requests.get(f'https://sentry.io/api/0/organizations/{configs.get("ORG_NAME").data}/combined-rules/', headers = headers)
        store_alerts(response.json())
        while response.links["next"]["results"] == "true":
            response = requests.get(response.links["next"]["url"], headers = headers)
            store_alerts(response.json())   
    except Exception as e:
        print(f'get_alerts: failed to call alert rules api - {e}')
        sys.exit()


def store_alerts(json_data):
    for alert in json_data:
        if "name" in alert:
            alert_list.append(alert["name"])
        else:
            logging.error('store_alerts: could not get existing alert name')

def get_projects():
    global headers
    try: 
        response = requests.get(f' https://sentry.io/api/0/organizations/{configs.get("ORG_NAME").data}/projects/', headers = headers)
        store_projects(response.json())

        while response.links["next"]["results"] == "true":
            response = requests.get(response.links["next"]["url"], headers = headers)
            store_projects(response.json()) 
    except Exception as e:
        logging.error(f'get_projects: unable to do get request - {e}')
        sys.exit()


def store_projects(json_data):
    global projects_dict

    for project in json_data:
        try:
            project_name = project["slug"]
            teams = project["teams"]
            projects_dict[project_name] = list()
       
            for team in teams:
                team_id = team["id"]
                projects_dict[project_name].append(team_id)
        except Exception as e:
            logging.error(f'create_project: could not get existing project names - {e}')
            script_report["exists"] += 1

def create_alerts():
    global headers
    global projects_dict
    global alert_list
    global script_report
    proj_team_list = []
    team_list = []
    script_report = {"success": 0, "failed": 0, "exists": 0}
    alert_rule_suffix = configs.get("ALERT_RULE_SUFFIX").data

    print('about to create alerts..')
    for proj_name, teams in projects_dict.items():
        for alert_name, payload in ISSUE_ALERTS.items():
            json = build_issue_alert_json(proj_name, alert_name, payload)
            create_alert(proj_name, alert_name, json, teams)
            
def create_alert(proj_name, alert_type, alert_payload_json, teams):
    alert_name = json.loads(alert_payload_json)["name"]
    if no_teams_assigned_to_project(teams):
        script_report["failed"] += 1
        logging.error(f'create_alert: failed to create alert for project: {proj_name} - No teams assigned to project')

    elif alert_already_exists(alert_name):
        script_report["exists"] += 1
        logging.info('create_alert: alert already exists for project ' + proj_name + '!') 
    else:
        alert_type = json.loads(alert_payload_json)["type"]
        alert_via_api(proj_name, alert_name, alert_payload_json, teams, alert_type)
        

def alert_via_api(proj_name, alert_name, json_data, teams, alert_type):
    if alert_type == 'issue':
        url = f'https://sentry.io/api/0/projects/{configs.get("ORG_NAME").data}/{proj_name}/rules/'
    elif alert_type == 'metric':
        # metric_alert_via_api(proj_name, alert_name, alert_payload_json, teams)
        url = "blah fake url"
    else:
        script_report["failed"] += 1
        logging.error(f'alert_via_api: no alert type detected for {alert_name}')
        return

    try:
        print(f'- Attempting to create alert: "{alert_name}"')
        response = requests.post(
                    url,
                    headers = headers, 
                    data=json_data)

        if(response.status_code in [200, 201]):
            script_report["success"] += 1
            logging.info('alert_via_api: Successfully created the metric alert ' + alert_name + ' for project: ' + proj_name)
        elif (response.status_code == 400):
            script_report["failed"] += 1
            logging.error('alert_via_api: could not create alert for project: ' + proj_name)
            logging.error(str(response.json()) + proj_name)
        elif (response.status_code == 403):
            logging.error('alert_via_apis: received the following status code: ' + str(response.status_code) + ' \nYou may be using your user level token without the necessary permissions.  \nPlease assign the AUTH_KEY to your org level token and refer to the README on how to create one.')
            sys.exit()
        else: 
            script_report["failed"] += 1
            logging.error('alert_via_api: received the following status code: ' + str(response.status_code) + ' for project: ' + proj_name)   

    except Exception as e:
        script_report["failed"] += 1
        logging.error(f'alert_via_api: failed to create alert for project : {proj_name} - {e}')
                   
    time.sleep(int(configs.get("SLEEP_TIME").data)/1000)

def no_teams_assigned_to_project(teams):
    return len(teams) == 0

def alert_already_exists(alert_name):
    return alert_name in alert_list

def build_issue_alert_json(proj_name, alert_name, payload):
    payload = jsons.loads(payload)
    payload['name'] = proj_name + " - " + alert_name
    return jsons.dumps(payload)

def main(argv):
    global alert_list
    global configs
    global headers
    global script_report
    global current_datetime

    do_setup()    
    get_alerts()
    get_projects()
    create_alerts()

    # Print final script status
    print("Script report:  ", script_report)
    print(f"Check log file alert_logfile_{current_datetime}.log for details.")
    
if __name__ == '__main__':
     main(sys.argv[1:])
