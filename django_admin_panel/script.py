import runpy
import sys
import time

time.sleep(2)
sys.argv = ['', 'migrate', 'movies', '--fake']
runpy.run_path('./manage.py', run_name='__main__')

sys.argv = ['', 'migrate']
runpy.run_path('./manage.py', run_name='__main__')

sys.argv = ['', 'collectstatic', '--noinput']
runpy.run_path('./manage.py', run_name='__main__')

runpy.run_path('./scripts/create_superuser.py', run_name='__main__')

runpy.run_path('./sqlite_to_postgres/load_data.py', run_name='__script__')
