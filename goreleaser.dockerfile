FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl wget && rm -rf /var/lib/apt/lists/*

# Download and install CloudHSM PKCS11 based on architecture
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    wget -q https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Noble/cloudhsm-pkcs11_latest_u24.04_amd64.deb && \
    apt install -y ./cloudhsm-pkcs11_latest_u24.04_amd64.deb && \
    rm cloudhsm-pkcs11_latest_u24.04_amd64.deb; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
    wget -q https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Noble/cloudhsm-pkcs11_latest_u24.04_arm64.deb && \
    apt install -y ./cloudhsm-pkcs11_latest_u24.04_arm64.deb && \
    rm cloudhsm-pkcs11_latest_u24.04_arm64.deb; \
    fi

# Add CloudHSM to PATH
ENV PATH="/opt/cloudhsm/bin:${PATH}"

# Create non-root user with configurable UID/GID
ARG UID=10000
ARG GID=10000
RUN groupadd -g ${GID} signatory && \
    useradd -u ${UID} -g signatory -m signatory && \
    mkdir -p /var/lib/signatory /etc/signatory && \
    chown -R signatory:signatory /var/lib/signatory /etc/signatory

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/signatory /bin/signatory
COPY ${TARGETPLATFORM}/signatory-cli /bin/signatory-cli

USER signatory
ENTRYPOINT ["/bin/signatory"]
