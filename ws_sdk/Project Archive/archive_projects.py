import logging
import os

import sys
from configparser import ConfigParser
from datetime import datetime, timedelta
import re
from ws_sdk.web import WS
from multiprocessing import Pool, Manager

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(levelname)s - %(asctime)s: - %(process)d: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger('urllib3').setLevel(logging.INFO)
logging.getLogger('ws_sdk').setLevel(logging.INFO)
logging.getLogger('chardet').setLevel(logging.INFO)

# WS_API_URL = os.getenv('WS_API_URL')
# WS_USER = os.getenv('WS_USER')
# WS_ORG = os.getenv('WS_ORG')

c_org = None
config = None
dry_run = False
report_types = {}
archive_dir = None
project_parallelism_level = 5


def get_reports_to_archive():
    products = c_org.get_all_products()
    total_p = len(products)
    excluded_products = config['DEFAULT']['ExcludedProductTokens'].strip().split(",")
    for prod in products:
        if prod['token'] in excluded_products:
            products.remove(prod)
    logging.info(f"{len(products)} Products to handle out of {total_p}")
    days_to_keep = timedelta(days=config.getint('DEFAULT', 'DaysToKeep'))
    archive_date = datetime.utcnow() - days_to_keep
    logging.info(f"Keeping {days_to_keep.days} days. Archiving projects older than {archive_date}")

    projects = []
    project_report_desc_list = []
    for prod in products:
        all_projects = c_org.get_all_projects(prod['token'])
        logging.info(f"Handling product: {prod['name']} number of projects: {len(all_projects)}")
        for project in all_projects:
            project_time = datetime.strptime(project['lastUpdatedDate'], "%Y-%m-%d %H:%M:%S +%f")
            if project_time < archive_date:
                logging.debug(f"Project {project['name']} Token: {project['token']} Last update: {project['lastUpdatedDate']} will be archived")
                project['project_archive_dir'] = os.path.join(os.path.join(archive_dir, project['productName']), project['name'])
                projects.append(project)
        logging.info(f"Found {len(projects)} projects to archive on product: {prod['name']}")

        for project in projects:
            if not os.path.exists(project['project_archive_dir']):
                os.makedirs(project['project_archive_dir'])
            for report_type in report_types.keys():
                project_report = project.copy()
                project_report['report_type'] = report_type
                project_report['report_full_name'] = os.path.join(project_report['project_archive_dir'], report_types[report_type])
                project_report_desc_list.append(project_report)

    return projects, project_report_desc_list


def generate_reports_manager(reports_desc_list):
    global project_parallelism_level
    logging.info(f"Generating {len(report_types)} report with {project_parallelism_level} processes")
    manager = Manager()
    failed_proj_tokens_q = manager.Queue()
    with Pool(processes=project_parallelism_level) as pool:
        pool.starmap(worker_generate_report, [(report_desc, c_org, failed_proj_tokens_q) for report_desc in reports_desc_list])

    failed_projects = set()
    while not failed_proj_tokens_q.empty():
        failed_projects.add(failed_proj_tokens_q.get(block=True, timeout=0.05))

    if failed_projects:
        logging.warning(f"{len(failed_projects)} projects were failed to archive")

    return failed_projects


def worker_generate_report(report_desc, connector, w_f_proj_tokens_q):
    logging.debug(f"Running report {report_desc['report_type']} on project: {report_desc['name']}. location: {report_desc['report_full_name']}")
    method_name = f"get_{report_desc['report_type']}"
    try:
        method_to_call = getattr(WS, method_name)
        # if method_name == 'get_inventory' and report_desc['token'] == '36f562ed68ac4e9ba3a8c67e5239633eb86b6fa2418f421e9a8c3ed1706d3277':   # TODO DELETE
        #     raise NameError
        global dry_run
        if not dry_run:
            logging.debug(f"Generating report: {report_desc['project_archive_dir']}")
            report = method_to_call(connector, token=report_desc['token'], report=True)
            f = open(report_desc['report_full_name'], 'bw')
            f.write(report)
        else:
            logging.info(f"[DRY_RUN] Generating report: {report_desc['project_archive_dir']}")
    except AttributeError:
        logging.error(f"report: {method_name} was not found")
    except Exception:
        logging.exception(f"Error producing report: {report_desc['report_type']} on project {report_desc['name']}. Project will not be deleted.")
        w_f_proj_tokens_q.put(report_desc['token'])


def delete_projects(proj_to_archive, failed_project_toks):
    projects_to_delete = proj_to_archive.copy()
    for project in projects_to_archive:
        if project['token'] in failed_project_toks:
            projects_to_delete.remove(project)
    logging.info(f"Out of {len(projects_to_archive)} projects, {len(projects_to_delete)} projects will be deleted")

    if projects_to_delete:
        global dry_run, c_org
        with Pool(processes=project_parallelism_level) as pool:
            pool.starmap(worker_delete_project, [(c_org, project, dry_run) for project in projects_to_delete])
        logging.info(f"{len(proj_to_archive)} projects deleted")


def worker_delete_project(conn, project, w_dry_run):
    if w_dry_run:
        logging.info(f"[DRY_RUN] Deleting project: {project['name']} Token: {project['token']}")
    else:
        logging.info(f"Deleting project: {project['name']} Token: {project['token']}")
        conn.delete(project['token'])


def parse_config(config_file):
    global config, dry_run, report_types, archive_dir, project_parallelism_level
    config = ConfigParser()
    config.optionxform = str
    config.read(config_file)

    project_parallelism_level = config['DEFAULT'].getint('ProjectParallelismLevel')
    dry_run = config['DEFAULT'].getboolean('DryRun')
    archive_dir = config['DEFAULT']['ArchiveDir']
    reports = config['DEFAULT']['Reports'].replace(' ', '').split(",")
    for report in reports:
        report_types[re.sub('_report.+', '', report)] = report


if __name__ == '__main__':
    start_time = datetime.now()
    if len(sys.argv) > 1:
        conf_file = sys.argv[-1]
    else:
        conf_file = 'params.config'
    logging.info(f"Using configuration file: {conf_file}")
    parse_config(conf_file)

    c_org = WS(api_url=config['DEFAULT']['WsApiUrl'], user_key=config['DEFAULT']['UserKey'], token=config['DEFAULT']['OrgToken'])
    if dry_run:
        logging.info("Running in DRY_RUN mode. Project will not be deleted and reports will not be generated!!")
    projects_to_archive, reports_to_archive = get_reports_to_archive()
    failed_project_tokens = generate_reports_manager(reports_to_archive)
    delete_projects(projects_to_archive, failed_project_tokens)

    logging.info(f"Script finished. Run time: {datetime.now() - start_time}")
