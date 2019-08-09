import express from 'express'
import cookieParser from 'cookie-parser'
import bodyParser from 'body-parser'
import { Issuer } from 'openid-client'

async function init () {
  require('dotenv').config()

  const app = express()

  app.use(cookieParser())
  app.use(bodyParser.json())

  const auth0Issuer = await Issuer.discover(process.env.AUTH0_DOMAIN)

  const client = new auth0Issuer.Client({
    client_id: process.env.AUTH0_CLIENT_ID,
    client_secret: process.env.AUTH0_CLIENT_SECRET,
    redirect_uris: ['http://localhost:3000/callback'],
    response_types: ['code']
  })

  app.get('/', (req, res) => {
    res.send('ok')
  })

  app.get('/login', (req, res) => {
    res.redirect(
      client.authorizationUrl({
        scope: 'openid email profile'
      })
    )
  })

  app.get('/callback', async (req, res) => {
    const params = client.callbackParams(req)

    const tokenSet = await client.callback(
      'http://localhost:3000/callback',
      params
    )
    console.log('received and validated tokens %j', tokenSet)
    console.log('validated ID Token claims %j', tokenSet.claims())
    res.send('ok')
  })
  const port = 3000

  app.listen(port, () => console.log(`Example app listening on port ${port}!`))
}

init()
