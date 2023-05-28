# Rawwater

sql injection challenge,
but using websockets so you can't just put on sqlmap,
and each team has their own sqlite3 in a postgres row
so they can't stomp on other teams or cause global problems

intended to run dockerized.
the `Dockerfile-dev`
has gubbins for local use and is intended to be where
you do any `mix` tasks and whatnot.
the `Dockerfile` is basically the normal elixir phoenix
release docker, with a couple dependencies for this chall
added in.
the compose file uses the `-dev` one;
prod used an off-the-shelf managed container platform
with managed postgres and no compose

sorry for the ai images,
ran out of time to get good irl ones

<3 vito

<vito@nautilus.institute>

<https://hackers.town/@vito>

## developing and running locally

use docker compose, this seems to work consistently:

```sh
# first time?
docker compose run --rm web mix ecto.migrate

docker compose up -d web
```

out of the box, the ticket
`ticket{22weatherdeckweatherdeckweatherdeck143032:fvhGh-7jS1MsxxF4YlB74MPdWSKZl0clNAmCKO8HgkcA6jN9}`
should work with the default challenge secret key in `config/runtime.ex`

should `mix dialyzer` clean, but `mix test` wasn't really used
(the solver is the test anyways)

## spoilers below

if you want to go in blind and solve this,
stop reading now!!!
fire up docker above, copy the ticket above,
and use it on `http://localhost:4000`

## implementation notes

`minibase.ex` handles the sqlite3 touching,
`tickets.ex` and `tickets/ticket.ex` are how that gets
mashed into postgres.
`hellform.ex` and `hellform/field.ex`
generate form fields based on the ticket seed,
validate their contents,
and generate sqlite3 sql for the minibase.


## solver notes

omg the solver will literally solve the challenge for a team
in a way where they can see the flag without solving it themselves

do not!!!!!!

anyways:

```sh
# run the solver against a dev instance
docker compose build solver && docker compose run --rm solver

# run the solver against a prod instance
docker compose run --rm \
  -e BASE_URL=https://example.invalid \
  -e TICKET=ticket(23asdf} \
  solver
```
