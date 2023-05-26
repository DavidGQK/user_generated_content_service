.DEFAULT_GOAL := help
help:
	$(info compose-up compose-build first-run app-bash webserver-bash postgres-shell django-migrate django-collectstatic)

compose-up:
	sudo docker-compose up

compose-build:
	sudo docker-compose build --force

first-run:
	sudo docker-compose exec app python script.py

app-bash:
	sudo docker-compose exec app bash

webserver-bash:
	sudo docker-compose exec web_server bash

postgres-shell:
	sudo docker-compose exec db psql -h 127.0.0.1 -U app -d movies_database

django-migrate:
	sudo docker-compose exec app python3 manage.py migrate

django-collectstatic:
	sudo docker-compose exec app python3 manage.py collectstatic --noinput
