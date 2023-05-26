import logging
import time

from elasticsearch import Elasticsearch

from functional.settings import test_settings
from functional.utils.backoff import backoff

logger = logging.getLogger(__name__)

if __name__ == '__main__':

    @backoff()
    def el():
        es = Elasticsearch(
            [f'{test_settings.es_host}:{test_settings.es_port}'],
            verify_certs=True)
        if es.ping():
            es.close()
            time.sleep(1)
            logging.error('INFO - Elastic connected.')
        else:
            raise Exception
    el()
