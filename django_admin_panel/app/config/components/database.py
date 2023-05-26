import os

from dotenv import load_dotenv

load_dotenv()

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB'),
        'USER': os.environ.get('POSTGRES_USER'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD'),
        'HOST': os.environ.get('POSTGRES_HOST'),
        'PORT': os.environ.get('POSTGRES_PORT'),
        'OPTIONS': {
            'options': '-c search_path=public,content'
        }
    }
}


# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': True,
#     'filters': {
#         'require_debug_true': {
#             '()': 'django.utils.log.RequireDebugTrue',
#         }
#     },
#     'formatters': {
#         'default': {
#             'format': '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
#         },
#     },
#     'handlers': {
#         'debug-console': {
#             'class': 'logging.StreamHandler',
#             'formatter': 'default',
#             'filters': ['require_debug_true'],
#         },
#     },
#     'loggers': {
#         'django.db.backends': {
#             'level': 'DEBUG',
#             'handlers': ['debug-console'],
#             'propagate': False,
#         }
#     },
# }
