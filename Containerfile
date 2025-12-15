# ROSA Boundary Container
# Fedora 43 with AWS CLI, OpenShift CLI, and AWS SSM Agent for Fargate
FROM fedora:43

# Install base packages including Fedora's AWS CLI
RUN dnf install -y \
    awscli2 \
    unzip \
    curl \
    tar \
    gzip \
    && dnf clean all

# Set up architecture-specific variables using uname
RUN ARCH=$(uname -m) && \
    echo "${ARCH}" > /tmp/aws_cli_arch && \
    if [ "${ARCH}" = "aarch64" ]; then \
      echo "-arm64" > /tmp/oc_suffix; \
    else \
      echo "" > /tmp/oc_suffix; \
    fi

# Register Fedora's AWS CLI with alternatives
RUN alternatives --install /usr/local/bin/aws aws /usr/bin/aws 10 --family fedora

# Download and install official AWS CLI
RUN AWS_CLI_ARCH=$(cat /tmp/aws_cli_arch) && \
    curl -o /tmp/awscliv2.zip "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_CLI_ARCH}.zip" && \
    unzip -q /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install --install-dir /opt/aws-cli-official --bin-dir /usr/local/bin/aws-cli-bin && \
    rm -rf /tmp/awscliv2.zip /tmp/aws

# Register official AWS CLI with alternatives
RUN alternatives --install /usr/local/bin/aws aws /opt/aws-cli-official/v2/current/bin/aws 20 --family aws-official

# Download and install OpenShift CLI versions 4.14-4.20
RUN OC_SUFFIX=$(cat /tmp/oc_suffix) && \
    for version in 4.14 4.15 4.16 4.17 4.18 4.19 4.20; do \
      mkdir -p /opt/openshift/${version} && \
      curl -sL "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-${version}/openshift-client-linux${OC_SUFFIX}.tar.gz" | \
        tar -xzf - -C /opt/openshift/${version} oc && \
      chmod +x /opt/openshift/${version}/oc; \
    done

# Register all OpenShift CLI versions with alternatives
# Priority increases with version number, 4.20 gets highest (100) to be default
RUN alternatives --install /usr/local/bin/oc oc /opt/openshift/4.14/oc 14 && \
    alternatives --install /usr/local/bin/oc oc /opt/openshift/4.15/oc 15 && \
    alternatives --install /usr/local/bin/oc oc /opt/openshift/4.16/oc 16 && \
    alternatives --install /usr/local/bin/oc oc /opt/openshift/4.17/oc 17 && \
    alternatives --install /usr/local/bin/oc oc /opt/openshift/4.18/oc 18 && \
    alternatives --install /usr/local/bin/oc oc /opt/openshift/4.19/oc 19 && \
    alternatives --install /usr/local/bin/oc oc /opt/openshift/4.20/oc 100

# Cleanup temporary files
RUN rm -f /tmp/aws_cli_arch /tmp/oc_suffix

# Set entrypoint for Fargate
ENTRYPOINT ["sleep", "infinity"]
