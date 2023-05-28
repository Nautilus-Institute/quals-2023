FROM mcr.microsoft.com/playwright:v1.33.0-jammy

RUN mkdir /solver
WORKDIR /solver

COPY package.json tsconfig.json /solver/
RUN npm i

COPY solver.ts /solver/

ENV \
        BROWSER=firefox \
        TICKET=ticket{22weatherdeckweatherdeckweatherdeck143032:fvhGh-7jS1MsxxF4YlB74MPdWSKZl0clNAmCKO8HgkcA6jN9} \
        BASE_URL=http://web:4000

CMD npx tsm solver.ts
