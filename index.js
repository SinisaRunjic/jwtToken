const express = require('express')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const users = [
  {
    id: '1',
    username: 'john',
    password: 'john1',
    isAdmin: true,
  }, {
    id: '2',
    username: 'jane',
    password: 'jane1',
    isAdmin: true,
  }
]

let refreshTokens = []

app.post("/api/refresh", (req, res) => {
  // take the refresh token from the user
  const refreshToken = req.body.token
  // send error if there isnt token or it is invalid
  if (!refreshToken) return res.status(401).json("You are not authenticated")
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json('Refresh token is not valid')
  }
  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    err && console.log(err)
    refreshTokens = refreshTokens.filter(token => token !== refreshToken)

    const newAccesToken = generateAccessToken(user)
    const newRefreshToken = generateRefreshToken(user)

    refreshTokens.push(newRefreshToken);
    res.status(200).json({
      accesToken: newAccesToken,
      refreshToken: newRefreshToken
    })
  })
  // everything ok create new access, refresh token and send to user
})

const generateAccessToken = (user) =>
  jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'mySecretKey', { expiresIn: '15m' })


const generateRefreshToken = (user) =>
  jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'myRefreshSecretKey')

app.post('/api/login', (req, res) => {
  const { username, password } = req.body
  const user = users.find(user => user.username === username && user.password === password)
  if (user) {
    // Generate acces token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken)
    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken
    })
  } else {
    res.status(400).json('User name or password are incorect')
  }
})

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization
  if (authHeader) {
    const token = authHeader.split(" ")[1]
    jwt.verify(token, "mySecretKey", (error, user) => {
      if (error) {
        return res.status(401).json('Token is not valid!')
      }

      req.user = user;
      next()
    })
  } else {
    res.status(401).json("You are not authenticated")
  }
}

app.post('/api/logout', verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter(token !== refreshToken)
  res.status(200).json("You logged succesfully")
})


app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted.");
  } else {
    res.status(403).json("You are not allowed to delete this user!");
  }
});

app.listen(5000, () => {
  console.log('Backend server')
})