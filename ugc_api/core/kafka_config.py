import logging

from kafka import KafkaAdminClient
from kafka.admin import KafkaAdminClient, NewTopic

from core.config import kafka_list_urls
from core.config import settings as SET
from services.backoff import backoff

logger = logging.getLogger(__name__)

kafka_kwargs = {'bootstrap_servers': kafka_list_urls,
                'client_id': SET.kafka_client}
logger.error('INFO -- kafka_kwargs -- %s', kafka_kwargs)


@backoff()
def kafka_init():
    """If there is no topic in kafka, it creates."""
    def test_topics():
        admin = KafkaAdminClient(**kafka_kwargs)
        kafka_list = admin.list_topics()
        for topic in SET.topic_list:
            if topic not in kafka_list:
                new_topic = NewTopic(name=topic,
                                     num_partitions=1,
                                     replication_factor=1)
                ad_resp = admin.create_topics(new_topics=[new_topic])
                logger.error('INFO - topic %s not exist, create topic - response: %s', topic, ad_resp)
            elif topic in kafka_list:
                logger.error('INFO - topic %s exist', topic)
        admin.close()
    test_topics()
