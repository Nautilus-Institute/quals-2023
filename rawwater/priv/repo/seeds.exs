# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# Inside the script, you can read and write to any of your
# repositories directly:
#
#     Rawwater.Repo.insert!(%Rawwater.SomeSchema{})
#
# We recommend using the bang functions (`insert!`, `update!`
# and so on) as they will fail if something goes wrong.

alias Rawwater.Repo
alias Rawwater.Products.Product

Repo.delete_all(Product)

[
  %Product{
    name: "iguana water",
    description: "water from under the iguana tree",
    price: 1595
  },
  %Product{
    name: "tap water",
    description: "too clean! has no good vibrations",
    price: 99
  },
  %Product{
    name: "upper deck toilet water",
    description: "homeopathy at work! good proximity",
    price: 149
  },
  %Product{
    name: "lower deck toilet water",
    description: "we're in business now",
    price: 299
  },
  %Product{
    name: "boat ramp water",
    description: "water from a big puddle in the parking lot at the boat ramp",
    price: 799
  },
  %Product{
    name: "bird bath water",
    description: "the birds like it and birds never get sick so that's good",
    price: 1995
  },
  %Product{
    name: "gutter water",
    description:
      "found this in front of barracudas on a thursday night, bit chunky",
    price: 2500
  },
  %Product{
    name: "fountain water",
    description:
      "got this from a fountain before i threw a bunch of frozen dishwasher detergent in it",
    price: 2195
  },
  %Product{
    name: "chicken water",
    description:
      "this is from the mud pit the chickies and piggies get fed, sometimes peafowl are there too",
    price: 2200
  },
  %Product{
    name: "barn water",
    description:
      "horses are big and strong so this water will make you big and strong",
    price: 3500
  },
  %Product{
    name: "lobster water",
    description: "i stole this from the grocery store lobster tank",
    price: 1701
  },
  %Product{
    name: "los angeles rain water",
    description: "suny los angeles baby!!!",
    price: 9905
  }
]
|> Enum.map(&Repo.insert/1)
