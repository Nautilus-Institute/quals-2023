CHAL_NAME?=$(shell basename $(shell pwd))


# Slugify challenge name
CHAL_SLUG=$(shell echo $(CHAL_NAME) | iconv -t ascii//TRANSLIT | sed -E -e 's/[^[:alnum:]]+/-/g' -e 's/^-+|-+$$//g' | tr '[:upper:]' '[:lower:]')

build: challenge
	mkdir -p build
	docker run -v $(shell pwd)/build:/buildout/ --rm -it $(CHAL_SLUG)-challenge:latest bash -c 'cp /build/* /buildout/.'

challenge:
	docker build -f dockers/challenge/Dockerfile -t $(CHAL_SLUG)-challenge:latest .
