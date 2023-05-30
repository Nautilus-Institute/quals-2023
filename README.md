# The DEF CON CTF 2023 Qualifier #

This repository contains the open source release for Nautilus Institute's 2023
DEF CON CTF qualifier.

We are releasing all of the source code for every challenge that was released
during the game. In most cases, this also includes all of the code required to
build that source code into a working challenge (such as `Makefile`s and
`Dockerfile`s). It *does not* include the infrastructure required to *host*
those challenges (e.g. our CI/CD pipeline, deployment scripts, and the
`gatekeeper` binary that validates tickets).

The `_images` folder contains the images that were on the scoreboar for each
of the challenges. Someone requested it, and this seemed like the best place
to put them.

## License ##

Everything in this repository, unless otherwise stated, is being released under
the MIT license. See [`LICENSE.md`](./LICENSE.md) for more details.

The `_images` folder is *probably* all licensable under Creative Commons
[BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). But, I (fuzyll)
am not 100% certain of the provenance of every image. Most were AI-generated,
but a few were not. So, user discretion is advised.

## Contact ##

Questions, comments, and/or concerns can be sent to
[@fuzyll](https://github.com/fuzyll), who is happy to direct things to the
appropriate party from there.
