if [ ! "$(docker network ls -f name=appsecpipeline_default | grep appsecpipeline_default)" ]; then
        docker network create --driver bridge appsecpipeline_default
fi
docker-compose up -d
echo "Adding allowed hosts to DefectDojo, assuming name: appsecpipeline_defectdojo_1. If the command fails double check the DefectDojo container name."
docker exec -ti appsecpipeline_defectdojo_1 sed -i  "s/ALLOWED_HOSTS = \[\]/ALLOWED_HOSTS = ['defectdojo.appsec.pipeline', 'localhost']/g" /opt/django-DefectDojo/dojo/settings.py
