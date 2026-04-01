# Simple Docker and Kubernetes example

This is a small and simple use case of Docker and Kubernetes, installing a simple API server with nginx

# Getting Started

The Main Dependencies are:

[Docker](https://www.docker.com/)

[Minikube](https://minikube.sigs.k8s.io/docs/start/)

[Docker Compose](https://docs.docker.com/compose/install/) (comes with Docker Desktop)

# Docker Compose

To run this simple example with Docker Compose, ensure Docker is running, then execute:

```bash
docker compose up --build
```

This will build the Flask API container and start both the Flask app and Nginx proxy. The API will be accessible at `http://localhost`.

# Kubernetes

To run this example with Kubernetes make sure you have Docker running, then start Minikube `$ minikube start` after that you can use the **setup.sh** script to run the API:

`$ ./setup.sh build` will build the Docker Image from the Dockerfile in **kube/flask**

`$ ./setup.sh start` will start the API

`$ ./setup.sh stop` will stop the API

`$ ./setup.sh restart` will restart the API

after starting the API you can do CTRL+C to exit and then do `$ minikube dashboard` to see the stats and number of pods of our kubernetes deployment