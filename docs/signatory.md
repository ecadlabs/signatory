# Signatory

## Configuration

Signatory configuration is specified in a yaml file. Use the `signatory.yaml`
file as a template to getting started.

Each backend can be configured with one of more instances of the backend. The
operator can add as many new backends as they wish, just append to the list.

### log_payloads

Setting the `log_payloads` to `true` will cause Signatory to log all operation
payloads to `stdout`. This may be desirable for audit and investigative
purposes.

## Metrics

Signatory exposes Prometheus metrics on port `9583`. Metrics include counters
and histograms  that track signing operations and errors.

The metrics are intended to be scraped using the Prometheus time series
database. We also publish a ready-made Grafana dashboard which users can use to
visualize the operation of their signing operations. (TODO: publish Grafana
dashboard)

## Liveness and Readiness checks

Signatory exposes a "liveness" and a "readiness" check, that runs on port 9583
by default. These endpoints can be used to test if the service is running
correctly, and ready to sign requests.

`localhost:9583/healthz/ready`
`localhost:9583/healthz/live`

Liveness and Readiness endpoints are useful for use in monitoring, or
declarative tests as part of deployment playbooks or kubernetes manifests.


