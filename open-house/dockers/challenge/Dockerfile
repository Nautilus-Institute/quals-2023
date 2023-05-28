# =============== Building Challenge In Docker  ===============
# If you want your challenge to rebuild every time you push to this repository,
# fill in the dependencies and commands in this top part of the Dockerfile
# If you want to do this, follow the steps below

# Choose your base distro to build the challenge on.
# Some examples: debian:bullseye, ubuntu:22.04, alpine:latest, fedora:latest
# Or any other base docker image
FROM ubuntu:23.10 AS builder

# Install any requirements needed to build, using the RUN command
# For example here are a few build tools and libraries
RUN apt-get update && \
    apt-get install -y build-essential crossbuild-essential-i386 clang zip

# This adds all files in the ./src directory. If you have files somewhere else, move them to ./src or add another COPY command below
COPY src /src

RUN mkdir /build && touch /build/.keepdir

WORKDIR /src

# This will run the script ./src/build.sh
# You can also change it to run any other command to perform the build
RUN if [ -f ./build.sh ]; then ./build.sh; fi

RUN touch .keepdir

# =============== Production Challenge Environment  ===============
# This part of the docker file defines the runtime environment for your challenge
# Please follow the steps below:

# CHAL AUTHOR: Choose your base distro to run the challenge on.
# Some examples: debian:bullseye, ubuntu:22.04, alpine:latest, fedora:latest
# Or any other base docker image
FROM ubuntu:23.10

# CHAL AUTHOR: If you have any runtime dependencies, install them here
# example: installing curl from apt
RUN apt-get update && apt-get install -y curl libc6-i386=2.37-0ubuntu2 adduser

# By default all the challenge files go into /opt/.

# Copy any files built using `./src/build.sh`
COPY --from=builder /build/* /opt/

# Copy all prebuilt files in ./bin/
COPY ./bin/* /opt/
RUN rm /opt/.keepdir -f

# Add a user to run the challenge (uid 1000)
RUN adduser --no-create-home --disabled-password --gecos "" user
USER user

# Set the working directory for the challenge
WORKDIR /opt

# CHAL AUTHOR: Command to run your challenge
CMD /opt/run_challenge.sh
