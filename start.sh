source ./env/bin/activate

redis-server &
python -OO api.py