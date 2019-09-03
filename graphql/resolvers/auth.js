const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const User = require('../../models/user')

module.exports = {
  createUser: async args => {
    try {
      const existingUser = await User.findOne({ email: args.userInput.email });
      if (existingUser) {
        throw new Error('User exists already.');
      }
      const hashedPassword = await bcrypt.hash(args.userInput.password, 12);

      const user = new User({
        email: args.userInput.email,
        password: hashedPassword
      });

      const result = await user.save();

      return { ...result._doc, password: null, _id: result.id };
    } catch (err) {
      throw err;
    }
  },

  login: async ({ email, password }) => {

    const user = await User.findOne({ email: email })
    if (!user) {
      throw new Error('User does not exist!')
    }

    const isEqual = await bcrypt.compare(password, user.password)
    if (!isEqual) {
      throw new Error('Password is incorrect!')
    }

    const token = await jwt.sign(
      { userId: user.id, email: user.email },
      'somesupersecretkey',
      {
        expiresIn: '1h'
      }
    )

    return { userId: user.id, token: token, tokenExpiration: 1 }
  }
}

// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1ZDZlOWUwZWJkOWRhOTA0ZWNhODhmMDIiLCJlbWFpbCI6InVzZXIzQGVtYWlsLmNvbSIsImlhdCI6MTU2NzUzMjA1MywiZXhwIjoxNTY3NTM1NjUzfQ.6A1bTrtASzvcFtCKmGe1EJCy3L7ZemBV6lkFZCTcNL0"
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1ZDZlOWUwZWJkOWRhOTA0ZWNhODhmMDIiLCJlbWFpbCI6InVzZXIzQGVtYWlsLmNvbSIsImlhdCI6MTU2NzUzMjY2NywiZXhwIjoxNTY3NTM2MjY3fQ.HV4vFQuQOACHxQQdn-T4esKBIGmYGig5sS8-3dmcK8o"