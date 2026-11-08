FROM python:3.7-slim

WORKDIR /apps
COPY msyh.ttc /usr/share/fonts/

# Update package list and install required packages
RUN apt-get update && apt-get install -y \
    libexif-dev \
    udev \
    chromium \
    vim \
    tzdata \
    libpcap-dev \
    default-jdk \
    && rm -rf /var/lib/apt/lists/*

#    tini \
# Set tini as the init process (PID 1)
# ENTRYPOINT ["/usr/bin/tini", "--"]


RUN pip install uro
# Copy the executable in the current directory into the container
COPY dist/ScopeSentry-Scan_linux_amd64_v1/ScopeSentry-Scan /apps/ScopeSentry-Scan
RUN chmod +x /apps/ScopeSentry-Scan
RUN mkdir /apps/ext
RUN mkdir /apps/ext/rad
RUN mkdir /apps/ext/ksubdomain
RUN mkdir /apps/ext/rustscan
RUN mkdir /apps/ext/katana

COPY tools/linux/ksubdomain /apps/ext/ksubdomain/ksubdomain
RUN chmod +x /apps/ext/ksubdomain/ksubdomain
COPY tools/linux/rad /apps/ext/rad/rad
RUN chmod +x /apps/ext/rad/rad
COPY tools/linux/rustscan /apps/ext/rustscan/rustscan
RUN chmod +x /apps/ext/rustscan/rustscan

COPY tools/linux/katana /apps/ext/katana/katana
RUN chmod +x /apps/ext/katana/katana
# Set time zone to Shanghai
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN echo 'Asia/Shanghai' >/etc/timezone

# Set encoding
ENV LANG C.UTF-8

# Command to run golang program
ENTRYPOINT ["/apps/ScopeSentry-Scan"]