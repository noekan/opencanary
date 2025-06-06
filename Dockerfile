FROM python:3.10-bullseye	

# Download cache lists and install minimal versions
RUN apt-get update && apt-get -yq install --no-install-recommends \
	# Required linux dependencies
	sudo vim build-essential libssl-dev libffi-dev python-dev libpcap-dev && \
	# Remove cache lists and clean up anything not needed to minimize image size
	apt-get autoremove -yq && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install required pip dependencies
RUN pip install opencanary
RUN pip install scapy pcapy-ng

# Set the default application we are running
ENTRYPOINT [ "opencanaryd" ]

# Set the default arguments to be used for the entrypoint
CMD [ "--dev", "--uid=nobody", "--gid=nogroup" ]
