# From a RHEL host with subscription management
FROM registry.redhat.io/openshift4/ose-jenkins-agent-maven
USER root
RUN curl -o /tmp/buildah.rpm https://rpmfind.net/linux/centos/8.3.2011/AppStream/x86_64/os/Packages/buildah-1.15.1-2.module_el8.3.0+475+c50ce30b.x86_64.rpm
RUN dnf install -y /tmp/buildah.rpm
RUN dnf install python3-pip
RUN pip3 install s3cmd
USER 1001
