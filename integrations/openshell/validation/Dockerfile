# Isolated probe workload; the marker is deliberately synthetic, not a credential.
FROM node:22-bookworm
COPY executor-ca.crt /usr/local/share/ca-certificates/authrail-validation-executor.crt
RUN mkdir -p /protected /sandbox && \
    printf 'synthetic-provider-credential-do-not-expose\n' > /protected/provider-marker && \
    chmod 0444 /protected/provider-marker && chmod 0777 /sandbox && update-ca-certificates
WORKDIR /sandbox
CMD ["sleep", "infinity"]
