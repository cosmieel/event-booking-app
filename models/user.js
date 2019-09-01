const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  createdEvents: [
    {
      type: Schema.Types.ObjectId,
      ref: 'Event'                       // event.js: mongoose.model('Event')
    }
  ]
})

module.exports = mongoose.model('User', userSchema)