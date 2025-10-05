#
# initializes the ace environment
# source bin/initialize-environment
#

source /venv/bin/activate

export SAQ_HOME=/opt/ace

if [ ! -d $SAQ_HOME ]; then
    echo "$SAQ_HOME does not exist -- did you mean to run this in the container?"
    exit 1
fi

cd $SAQ_HOME
export PATH="$PATH:$SAQ_HOME:$SAQ_HOME/bin:/opt/site/bin"

if [ -e "load_local_environment" ]
then
    source "load_local_environment"
fi
