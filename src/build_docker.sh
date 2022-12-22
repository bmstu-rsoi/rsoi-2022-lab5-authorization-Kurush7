version=1.0

docker buildx build --push -t kurushpondoxocrow/rsoi-library:$version -f LibraryDockerfile .
docker buildx build --push -t kurushpondoxocrow/rsoi-rating:$version -f RatingDockerfile .
docker buildx build --push -t kurushpondoxocrow/rsoi-reservation:$version -f ReservationDockerfile .
docker buildx build --push -t kurushpondoxocrow/rsoi-api:$version -f ApiDockerfile .