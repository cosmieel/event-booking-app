const express = require('express');
const bodyParser = require('body-parser');
const graphqlHttp = require('express-graphql');
const { buildSchema } = require('graphql');
const mongoose = require('mongoose');

const PORT = 3000;

const app = express()

const events = []

app.use(bodyParser.json())

app.use(
  '/graphql', 
  graphqlHttp({

    schema: buildSchema(`
      type Event {
        _id: ID!
        title: String!
        description: String!
        price: Float!
        date: String!
      }

      input EventInput {
        title: String!
        description: String!
        price: Float!
        date: String!
      }

      type RootQuery {
        events: [Event!]!
      }

      type RootMutation {
        createEvent(eventInput: EventInput): Event
      }

      schema {
        query: RootQuery
        mutation: RootMutation
      }
    `),

    rootValue: {

      events: () => {
        return events
      },

      createEvent: (args) => {
        const event = {
          _id: Math.random().toString(),
          title: args.eventInput.title,
          description: args.eventInput.description,
          price: +args.eventInput.price,
          date: args.eventInput.date
        };

        events.push(event)

        return event
   
      }
    },

    graphiql: true
  })
)


mongoose.connect(
  `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@ddaniil-cluster-vas1i.mongodb.net/test?retryWrites=true&w=majority`, { useNewUrlParser: true }
).then(() => {
  app.listen(PORT, () => {
    console.log(`Running the app on port: ${PORT}`)
  })
}).catch(err => {
  console.log(err)
})


