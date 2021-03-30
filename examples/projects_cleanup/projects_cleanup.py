import logging
import os
import re
import sys
from configparser import ConfigParser
from datetime import datetime, timedelta
from multiprocessing import Manager
from multiprocessing.pool import ThreadPool
from ws_sdk.web import WS

logging.basicConfig(level=logging.INFO, filename='cleanup.log', format='%(levelname)s %(asctime)s %(thread)d: %(message)s', datefmt='%y-%m-%d %H:%M:%S')

c_org = None
config = None
dry_run = False
report_types = {}
archive_dir = None
project_parallelism_level = 5


def get_reports_to_archive():
    products = c_org.get_products()
    excluded_products = config['DEFAULT']['ExcludedProductTokens'].strip().split(",")
    for prod in products:
        if prod['token'] in excluded_products:
            products.remove(prod)
    logging.info(f"{len(products)} Products to handle out of {len(products)}")
    days_to_keep = timedelta(days=config.getint('DEFAULT', 'DaysToKeep'))
    archive_date = datetime.utcnow() - days_to_keep
    logging.info(f"Keeping {days_to_keep.days} days. Archiving projects older than {archive_date}")

    all_projects = []
    project_report_desc_list = []
    for prod in products:                                 # Creating list of all reports of all projects to be produced
        curr_prod_proj_to_archive = []
        curr_prod_projects = c_org.get_projects(prod['token'])
        logging.info(f"Handling product: {prod['name']} number of projects: {len(curr_prod_projects)}")
        for project in curr_prod_projects:
            project_time = datetime.strptime(project['lastUpdatedDate'], "%Y-%m-%d %H:%M:%S +%f")
            if project_time < archive_date:
                logging.debug(f"Project {project['name']} Token: {project['token']} Last update: {project['lastUpdatedDate']} will be archived")
                project['project_archive_dir'] = os.path.join(os.path.join(archive_dir, project['productName']), project['name'])
                curr_prod_proj_to_archive.append(project)

        logging.info(f"Found {len(curr_prod_proj_to_archive)} projects to archive on product: {prod['name']}")

        for project in curr_prod_proj_to_archive:           # Creating list of report to-be-produced meta data
            if not os.path.exists(project['project_archive_dir']):
                os.makedirs(project['project_archive_dir'])
            for report_type in report_types.keys():
                project_report = project.copy()
                project_report['report_type'] = report_type
                project_report['report_full_name'] = os.path.join(project_report['project_archive_dir'], report_types[report_type])
                project_report_desc_list.append(project_report)

        all_projects = all_projects + curr_prod_proj_to_archive
    logging.info(f"Found total {len(all_projects)} projects to archive ({len(project_report_desc_list)} reports will be produced)")

    return all_projects, project_report_desc_list


def generate_reports_manager(reports_desc_list):
    global project_parallelism_level
    manager = Manager()
    failed_proj_tokens_q = manager.Queue()
    with ThreadPool(processes=project_parallelism_level) as pool:
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
        global dry_run
        if dry_run:
            logging.info(f"[DRY_RUN] Generating report: {report_desc['project_archive_dir']}")
        else:
            logging.debug(f"Generating report: {report_desc['project_archive_dir']}")
            report = method_to_call(connector, token=report_desc['token'], report=True)
            f = open(report_desc['report_full_name'], 'bw')
            f.write(report)
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
        with ThreadPool(processes=1) as thread_pool:
            thread_pool.starmap(worker_delete_project, [(c_org, project, dry_run) for project in projects_to_delete])
        logging.info(f"{len(proj_to_archive)} projects deleted")


def worker_delete_project(conn, project, w_dry_run):
    if w_dry_run:
        logging.info(f"[DRY_RUN] Deleting project: {project['name']} Token: {project['token']}")
    else:
        logging.info(f"Deleting project: {project['name']} Token: {project['token']}")
        conn.delete_scope(project['token'])


def parse_config(config_file):
    global config, dry_run, report_types, archive_dir, project_parallelism_level
    config = ConfigParser()
    config.optionxform = str
    config.read(config_file)

    project_parallelism_level = config['DEFAULT'].getint('ProjectParallelismLevel')
    dry_run = config['DEFAULT'].getboolean('DryRun')
    archive_dir = config['DEFAULT']['ReportsDir']
    reports = config['DEFAULT']['Reports'].replace(' ', '').split(",")
    for report in reports:                                          # Generate SDK methods from the conf report list
        report_types[re.sub('_report.+', '', report)] = report
    logging.info(f"Generating {len(report_types)} report types with {project_parallelism_level} threads")


if __name__ == '__main__':
    start_time = datetime.now()
    if len(sys.argv) > 1:
        conf_file = sys.argv[-1]
    else:
        conf_file = 'params.config'
    logging.info(f"Using configuration file: {conf_file}")
    parse_config(conf_file)
    c_org = WS(url=config['DEFAULT']['WsUrl'],
               user_key=config['DEFAULT']['UserKey'],
               token=config['DEFAULT']['OrgToken'],
               timeout=300)
    if dry_run:
        logging.info("Running in DRY_RUN mode. Project will not be deleted and reports will not be generated!!!")
    projects_to_archive, reports_to_archive = get_reports_to_archive()
    failed_project_tokens = []
    if config['DEFAULT'].getboolean('SkipReportGeneration'):
        logging.info("Skipping Report Generation")
    else:
        failed_project_tokens = generate_reports_manager(reports_to_archive)
    delete_projects(projects_to_archive, failed_project_tokens)

    logging.info(f"Project Cleanup finished. Run time: {datetime.now() - start_time}")
