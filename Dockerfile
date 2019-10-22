#FROM kobotoolbox/koboform_base:latest
FROM nikolaik/python-nodejs:python3.8-nodejs12

ENV DEBIAN_FRONTEND noninteractive
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

ENV KPI_LOGS_DIR=/srv/logs \
    KPI_WHOOSH_DIR=/srv/whoosh \
    BUILD_DIR=/srv/build \
    FONTS_DIR=/srv/fonts \
    WEBPACK_STATS_PATH=/srv/webpack-stats.json \
    DJANGO_SETTINGS_MODULE=kobo.settings.prod \
    # The mountpoint of a volume shared with the `nginx` container. Static files will
    #   be copied there.
    NGINX_STATIC_DIR=/srv/static \
    KPI_SRC_DIR=/srv/src/kpi \
    KPI_NODE_PATH=/srv/node_modules \
    PIP_DIR=/srv/pip \
    TMP_DIR=/srv/tmp


# Install Dockerize.
ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz -P /tmp \
    && tar -C /usr/local/bin -xzvf /tmp/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm /tmp/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz


##########################################
# Create build directories               #
##########################################
RUN mkdir -p "${BUILD_DIR}" && \
    mkdir -p "${FONTS_DIR}" && \
    mkdir -p "${NGINX_STATIC_DIR}" && \
    mkdir -p "${KPI_SRC_DIR}" && \
    mkdir -p "${KPI_NODE_PATH}" && \
    mkdir -p "${PIP_DIR}" && \
    mkdir -p "${TMP_DIR}"


##########################################
# Install `apt` packages.                #
##########################################

RUN apt -qq update && \
    apt -qq -y install \
        default-jre-headless \
        gdal-bin \
        libproj-dev \
        fontforge \
        gettext \
        ttfautohint \
        postgresql-client \
        locales \
        vim && \
    apt clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


###########################
# Install locales         #
###########################
RUN locale-gen en_US.UTF-8 && dpkg-reconfigure locales


###########################
# Install `pip` packages. #
###########################

RUN pip freeze > /srv/tmp/base_os_dependencies.txt
RUN pip install  --quiet --upgrade pip && \
    pip install  --quiet pip-tools
COPY ./dependencies/pip/requirements.in /srv/tmp/base__external_services.txt
#RUN pip-sync /srv/tmp/base_os_dependencies.txt /srv/tmp/base__external_services.txt 1>/dev/null && \
#    rm -rf ~/.cache/pip
RUN pip install -r /srv/tmp/base__external_services.txt && \
    rm -rf ~/.cache/pip


###########################
# Install `npm` packages. #
###########################

COPY ./package.json ${KPI_SRC_DIR}/
WORKDIR ${KPI_SRC_DIR}/
RUN ln -s "${KPI_NODE_PATH}" "${KPI_SRC_DIR}/node_modules" && \
    npm install --quiet && \
    npm cache clean --force # && \
    #mv "${KPI_SRC_DIR}/package.json" /srv/tmp/base_package.json
ENV PATH $PATH:${KPI_NODE_PATH}/.bin

###########################
# Re-sync `pip` packages. #
###########################

# COPY ./dependencies/pip/external_services.txt "${KPI_SRC_DIR}/dependencies/pip/"
# WORKDIR ${PIP_DIR}/

# Only install if the current version of `dependencies/pip/external_services.txt` differs from the one used in the base image.
# RUN if ! diff "${KPI_SRC_DIR}/dependencies/pip/external_services.txt" /srv/tmp/base__external_services.txt; then \
#        pip-sync /srv/tmp/base_os_dependencies.txt "${KPI_SRC_DIR}/dependencies/pip/external_services.txt" 1>/dev/null \
#    ; fi


##########################################
# Install any additional `npm` packages. #
##########################################

#COPY ./package.json "${KPI_SRC_DIR}/"
#WORKDIR ${KPI_SRC_DIR}/
# Only install if the current version of `package.json` differs from the one used in the base image.
#RUN if ! diff "${KPI_SRC_DIR}/package.json" /srv/tmp/base_package.json; then \
#        # Try error-prone `npm install` step twice.
#        npm install --quiet || npm install --quiet \
#    ; fi


######################
# Build client code. #
######################

COPY ./scripts/copy_fonts.py ${KPI_SRC_DIR}/scripts/copy_fonts.py
COPY ./scripts/generate_icons.js ${KPI_SRC_DIR}/scripts/generate_icons.js
COPY ./webpack ${KPI_SRC_DIR}/webpack
COPY ./.eslintrc.json ${KPI_SRC_DIR}/.eslintrc.json
COPY ./.stylelintrc.json ${KPI_SRC_DIR}/.stylelintrc.json
COPY ./test ${KPI_SRC_DIR}/test
COPY ./jsapp ${KPI_SRC_DIR}/jsapp
COPY ./webpack-stats.json ${WEBPACK_STATS_PATH}

RUN ln -s "${BUILD_DIR}" "${KPI_SRC_DIR}/jsapp/compiled" && \
    rm -rf "${KPI_SRC_DIR}/jsapp/fonts" && \
    ln -s "${FONTS_DIR}" "${KPI_SRC_DIR}/jsapp/fonts" # && \
    # FIXME: Move `webpack-stats.json` to some build target directory so these ad-hoc workarounds don't continue to accumulate.
    ln -s "${WEBPACK_STATS_PATH}" webpack-stats.json

RUN npm run copy-fonts && npm run build

###############################################
# Copy over this directory in its current state. #
###############################################

RUN rm -rf "${KPI_SRC_DIR}"
COPY . "${KPI_SRC_DIR}"

# Restore the backed-up package installation directories.
RUN ln -s "${KPI_NODE_PATH}" "${KPI_SRC_DIR}/node_modules" && \
    ln -s "${BUILD_DIR}" "${KPI_SRC_DIR}/jsapp/compiled" && \
    ln -s "${FONTS_DIR}" "${KPI_SRC_DIR}/jsapp/fonts" && \
    ln -s "${WEBPACK_STATS_PATH}" webpack-stats.json


###########################
# Organize static assets. #
###########################

RUN python manage.py collectstatic --noinput


#####################################
# Retrieve and compile translations #
#####################################

RUN git submodule init && \
    git submodule update --remote && \
    python manage.py compilemessages


#################################################################
# Persist the log directory, email directory, and Whoosh index. #
#################################################################

RUN mkdir -p "${KPI_LOGS_DIR}/" "${KPI_WHOOSH_DIR}/" "${KPI_SRC_DIR}/emails"


#################################################
# Handle runtime tasks and create main process. #
#################################################

# Using `/etc/profile.d/` as a repository for non-hard-coded environment variable overrides.
RUN echo 'source /etc/profile' >> /root/.bashrc

# FIXME: Allow Celery to run as root ...for now.
ENV C_FORCE_ROOT="true"

# Do it even if we don't why yet.
RUN useradd -s /bin/false -m wsgi

# Prepare for execution.
RUN ln -s "${KPI_SRC_DIR}/docker/init.bash" /etc/my_init.d/10_init_kpi.bash && \
    rm -rf /etc/service/wsgi && \
    mkdir -p /etc/service/uwsgi && \
    ln -s "${KPI_SRC_DIR}/docker/run_uwsgi.bash" /etc/service/uwsgi/run && \
    mkdir -p /etc/service/celery && \
    ln -s "${KPI_SRC_DIR}/docker/run_celery.bash" /etc/service/celery/run && \
    mkdir -p /etc/service/celery_beat && \
    ln -s "${KPI_SRC_DIR}/docker/run_celery_beat.bash" /etc/service/celery_beat/run && \
    mkdir -p /etc/service/celery_sync_kobocat_xforms && \
    ln -s "${KPI_SRC_DIR}/docker/run_celery_sync_kobocat_xforms.bash" /etc/service/celery_sync_kobocat_xforms/run

EXPOSE 8000
