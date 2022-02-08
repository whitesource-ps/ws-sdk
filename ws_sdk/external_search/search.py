import json
import logging
from abc import abstractmethod, ABC
from datetime import datetime
from functools import lru_cache
from string import Template
from typing import List

import requests
from cachetools import keys, cached

from ws_sdk.ws_constants import *

logger = logging.getLogger(__name__)


def hashable_key(*args, **kwargs):
    for k, v in kwargs.items():
        if isinstance(v, (list, dict)):
            logger.debug(f"The value of key: {k} is un-hashable. Converting to string")
            kwargs[k] = str(v)

    return keys.hashkey(*args, **kwargs)


class ExtSearch:
    def load_search_class(self, registry_name: str, **kwargs):
        class_name = f"{registry_name.capitalize()}Search"
        try:
            search_class = globals()[class_name]
        except KeyError:
            logger.error(f"'{registry_name}' is unsupported")
            raise NotImplementedError
        logger.info(f"Searching in '{search_class.repo_name}'")

        return search_class(**kwargs)

    @cached(cache=lru_cache(maxsize=Cache.CACHE_SIZE), key=hashable_key)
    def _search(self, **kwargs) -> list:
        try:
            artifact_registry = LibMetaData.LANG_TO_L_TYPE[kwargs['type'].lower()].registry_name
            if not artifact_registry:
                raise KeyError
        except KeyError:
            logger.error(f"Cannot search: '{kwargs.get('artifactId')}' Of type: '{kwargs.get('type')}' type is unsupported")
            raise NotImplementedError

        search_o = self.load_search_class(artifact_registry, **kwargs)
        search_o.search()

        return search_o

    def search(self, **kwargs) -> List[dict]:
        search_o = self._search(**kwargs)

        return search_o.search_results

    def get_lib_publish_date(self, **kwargs) -> list:
        search_o = self._search(**kwargs)

        return search_o.publish_date if search_o else None


class RegistrySearchTemplate(ABC):
    repo_name: str
    template_url: str
    search_results: str = None
    url: str
    mutual_mandatory_fields = {'groupId', 'version'}
    mandatory_fields = {}

    def __init__(self, **kwargs):
        self.mandatory_fields = set.union(self.mandatory_fields, self.mutual_mandatory_fields)
        self.check_mandatory_fields(**kwargs)

    @property
    @abstractmethod
    def publish_date(self): raise NotImplementedError

    @abstractmethod
    def handle_resp(self, ret): raise NotImplementedError

    def call_search_api(self) -> dict:
        try:
            resp = requests.get(self.url)
        except requests.exceptions.RequestException:
            raise

        try:
            ret = json.loads(resp.text)
        except json.JSONDecodeError:
            ret = resp.text

        return ret

    def search(self):
        ret = self.call_search_api()

        return self.handle_resp(ret)

    def check_mandatory_fields(self, **kwargs):
        for field in self.mandatory_fields:
            try:
                if not kwargs[field]:
                    raise KeyError
            except KeyError:
                logger.error(f"Missing Key value for search: '{field}'")
                raise


class MavenSearch(RegistrySearchTemplate):
    repo_name = "Maven"
    template_url = Template("https://search.maven.org/solrsearch/select?q=g:$group%20AND%20a:$artifact%20AND%20v:$version%20AND%20l:javadoc%20AND%20p:jar&rows=20&wt=json")
    mandatory_fields = {'artifactId'}

    def __init__(self, **kwargs):
        super(self.__class__, self).__init__(**kwargs)
        self.url = self.template_url.substitute(artifact=kwargs['artifactId'], group=kwargs['groupId'], version=kwargs['version'])

    @property
    def publish_date(self) -> datetime:
        return datetime.fromtimestamp(self.search_results[0]['timestamp'] / 1000) if self.search_results else None

    def handle_resp(self, ret):
        self.search_results = ret['response']['docs']
        if self.search_results is None:
            raise ValueError


class PypiSearch(RegistrySearchTemplate):
    repo_name = "PyPi"
    url = Template("https://pypi.org/pypi/$name/$version/json")
    mandatory_fields = {}

    def __init__(self, **kwargs):
        super(self.__class__, self).__init__(**kwargs)
        self.url = self.url.substitute(name=kwargs['groupId'], version=kwargs['version'])
        self.version = kwargs['version']

    @property
    def publish_date(self) -> datetime:
        return datetime.strptime(self.search_results[0]['upload_time_iso_8601'], "%Y-%m-%dT%H:%M:%S.%fZ") if self.search_results else None

    def handle_resp(self, ret):
        self.search_results = ret["releases"][self.version]


class NpmSearch(RegistrySearchTemplate):
    repo_name = "NPM"
    template_url = "https://api.npms.io/v2/package/$name"

    def __init__(self, **kwargs):
        super(self.__class__, self).__init__(**kwargs)
        self.url = self.url.substitute(name=kwargs['artifactId'])

    def handle_resp(self, ret):
        print("ret")

    @property
    def publish_date(self) -> datetime:
        pass
