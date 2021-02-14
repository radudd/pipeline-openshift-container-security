FROM docker.io/openshift/jenkins-agent-maven-35-centos7:v3.11
#FROM quay.io/openshift/origin-jenkins-agent-maven:4.8
#FROM registry.redhat.io/openshift4/ose-jenkins-agent-maven
USER root
RUN yum install -y skopeo buildah podman gpg2 python3-pip
RUN pip3 install s3cmd
USER 1001
