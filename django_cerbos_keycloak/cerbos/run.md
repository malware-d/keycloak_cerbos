docker run --rm --name cerbos \
  -v $(pwd)/cerbos/policies:/policies \
  -v $(pwd)/cerbos/conf.yaml:/etc/cerbos/conf.yaml \
  -p 3592:3592 \
  -p 3593:3593 \
  -p 3597:3597 \
  ghcr.io/cerbos/cerbos:latest \
  server --config=/etc/cerbos/conf.yaml


docker run --rm -v $(pwd)/cerbos/policies:/policies ghcr.io/cerbos/cerbos:latest compile /policies
