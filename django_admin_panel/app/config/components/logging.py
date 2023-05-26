import os

LOGGER_HOST = os.environ.get('LOGSTASH_HOST', 'logstash')
LOGGER_PORT = int(os.environ.get('LOGSTASH_PORT', 5044))
LOG_LEVEL = 'INFO'

LOGGING = {
  'version': 1,
  'disable_existing_loggers': False,
  'formatters': {
      'simple': {
            'format': 'velname)s %(message)s'
        },
  },
  'handlers': {
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'logstash': {
            'level': LOG_LEVEL,
            'class': 'logstash.LogstashHandler',
            'host': LOGGER_HOST,
            'port': LOGGER_PORT, 
            'version': 1,
            'message_type': 'django',
            'fqdn': False,
            'tags': ['django'],
        },
  },
  'loggers': {
        'django.request': {
            'handlers': ['logstash'],
            'level': LOG_LEVEL,
            'propagate': True,
        },
    },
    # 'root': {
    #     'handlers': ['logstash'],
    #     'level': LOG_LEVEL,
    # }
}
