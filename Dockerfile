FROM python:3.10-alpine

LABEL org.opencontainers.image.authors="Tobias Hargesheimer <docker@ison.ws>" \
    #org.opencontainers.image.version="${VCS_REF}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.title="WH-Mainz Internet Login" \
    org.opencontainers.image.description="Wohnheime Mainz Internet Login/Logout HTTPD (AlpineLinux with Python3)" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.url="ghcr.io/tob1as/internetloginwithpythonwebservice:latest" \
    org.opencontainers.image.source="https://github.com/Tob1as/internetloginwithpythonwebservice"

SHELL ["/bin/sh", "-euxo", "pipefail", "-c"]

COPY login_wohnheim_uni_mainz_de-webservice.py /service/login_wohnheim_uni_mainz_de-webservice.py

RUN \
    addgroup --gid 1000 webserver ; \
    adduser --system --shell /bin/sh --uid 1000 --ingroup webserver --home /service webserver ; \
    chown webserver:webserver /service/login_wohnheim_uni_mainz_de-webservice.py ; \
    chmod +x /service/login_wohnheim_uni_mainz_de-webservice.py ; \
    pip3 install --no-cache-dir requests ; \
    pip3 install --no-cache-dir beautifulsoup4

WORKDIR /service
USER webserver
STOPSIGNAL SIGINT
EXPOSE 8000

CMD ["python3", "-u", "./login_wohnheim_uni_mainz_de-webservice.py"]