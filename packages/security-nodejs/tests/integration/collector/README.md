# OTLP logs collector check

The collector check uses a disposable OpenTelemetry Collector container on a
private Docker network. It does not publish a host port and it only removes
the network and container IDs created by its own script. Use the same pinned
collector image as the release environment and point the log exporter at
`http://collector:4318/v1/logs`.

The output file must contain an actual OTLP logs export from the Node process.
An application stdout line or a hand-written JSON fixture is not accepted as
collector evidence. Keep the collector output path with the matrix result.
