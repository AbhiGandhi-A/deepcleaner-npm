FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
# Insecure curl pipe to bash and missing USER directive
RUN curl -fsSL https://example.com/install.sh | bash
CMD ["/bin/bash"]

