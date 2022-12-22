postgresPod=$1

cat test/libraries.dump           | kubectl exec -i $postgresPod -- psql -U program libraries
cat test/ratings.dump        | kubectl exec -i $postgresPod -- psql -U program ratings
cat test/reservations.dump           | kubectl exec -i $postgresPod -- psql -U program reservations