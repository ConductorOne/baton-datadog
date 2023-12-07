FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-datadog"]
COPY baton-datadog /