import express from 'express'
import cookieParser from 'cookie-parser'
import bodyParser from 'body-parser'
import { Issuer } from 'openid-client'
import uuid from 'uuidv4'
import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'

require('dotenv').config()

const jwks = jwksClient({
  jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
})

const sessionStore = {}

function getSigningKey (header) {
  return new Promise((resolve, reject) => {
    jwks.getSigningKey(header.kid, function (err, key) {
      if (err) {
        return reject(err)
      }

      const signingKey = key['publicKey'] || key['rsaPublicKey']
      resolve(signingKey)
    })
  })
}

async function verifyAccessToken (token) {
  const decodedToken = jwt.decode(token, { complete: true })
  const signingKey = await getSigningKey(decodedToken.header)
  return jwt.verify(token, signingKey)
}

async function protectMiddleware (req, res, next) {
  let hasSession = false

  // does the user have a session?
  const session = sessionStore[req.cookies['sid']]

  if (session) {
    hasSession = true
  } else if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer ')
  ) {
    const token = req.headers.authorization.split(' ')[1]

    // check for token bearer in the auth header instead
    try {
      await verifyAccessToken(token)
      hasSession = true
    } catch (e) {
      console.error(e)
    }
  }

  if (!hasSession) {
    return res.redirect('/login')
  }

  next()
}

// make sure your auth0 app
// Token Endpoint Authentication Method = Basic
// Allowed Callback Urls = http://localhost:3000/callback
// Allowed Logout Urls = http://localhost:3000
// Advanced > OIDC Conformant enabled

// Then make sure you create an API Audience in Auth0
// with the audience / identifer as http://localhost:3000
// enable RBAC
// enable Add permissions in access token
// this allows us to use the 'audience' specifier
// and get a JWT-based access token
async function init () {
  const app = express()

  app.use(cookieParser())
  app.use(bodyParser.json())

  const auth0Issuer = await Issuer.discover(
    `https://${process.env.AUTH0_DOMAIN}`
  )
  auth0Issuer['end_session_endpoint'] = `https://${
    process.env.AUTH0_DOMAIN
  }/v2/logout`

  const client = new auth0Issuer.Client({
    client_id: process.env.AUTH0_CLIENT_ID,
    client_secret: process.env.AUTH0_CLIENT_SECRET,
    redirect_uris: ['http://localhost:3000/callback'],
    response_types: ['code']
  })

  app.get('/', (req, res) => {
    const session = sessionStore[req.cookies['sid']]

    if (!session) {
      return res.send('<a href="/login">Login here</a>')
    }

    res.write(`<html>
  <p>Session id: ${req.cookies['sid']}</p>
  <textarea style="min-height: 20rem; width: 75%;">${JSON.stringify(
    session,
    null,
    2
  )}</textarea>
  <p>
    <a href="/protected">Protected route</a>
  </p>  
  
  <p>
    <a href="/logout">logout</a>
  </p>
</html>`)
    res.end()
  })

  app.get('/login', (req, res) => {
    const sessId = uuid()
    const csrf = uuid()

    sessionStore[sessId] = {
      csrf
    }

    res.cookie('sid', sessId)

    res.redirect(
      client.authorizationUrl({
        scope: 'openid email profile',
        state: csrf,
        audience: 'http://localhost:3000'
      })
    )
  })

  app.get('/callback', async (req, res) => {
    const params = client.callbackParams(req)

    const session = sessionStore[req.cookies['sid']]

    if (!session) {
      return res.send('no session')
    }

    const state = session.csrf
    let tokenSet

    try {
      tokenSet = await client.callback(
        'http://localhost:3000/callback',
        params,
        {
          state,
          response_type: 'code'
        }
      )
    } catch (e) {
      return res.send('Login validation failure:' + e.message)
    }

    delete session.csrf

    session['tokenSet'] = {
      access_token: tokenSet.access_token,
      id_token: tokenSet.id_token,
      scope: tokenSet.scope,
      expires_at: tokenSet.expires_at,
      token_type: tokenSet.token_type
    }

    session['claims'] = tokenSet.claims

    res.redirect('/')
  })

  app.get('/logout', (req, res) => {
    const session = sessionStore[req.cookies['sid']]

    if (!session) {
      return res.redirect('/')
    }

    delete sessionStore[req.cookies['sid']]

    res.redirect(
      client.endSessionUrl({
        // https://auth0.com/docs/api/authentication?javascript#logout
        // couldn't get the "Allowed Logout URLs" to work, so including client id
        client_id: process.env.AUTH0_CLIENT_ID,
        id_token_hint: session.tokenSet.id_token,
        // auth0 does not support post_logout_redirect_uri
        // https://community.auth0.com/t/conform-to-openid-logout-to-use-post-logout-redirect-uri-instead-of-returnto/16233
        // use returnTo instead
        returnTo: 'http://localhost:3000'
      })
    )
  })

  app.get('/protected', protectMiddleware, (req, res) => {
    res.send('protected endpoint')
  })

  const port = 3000

  app.listen(port, () => console.log(`Example app listening on port ${port}!`))
}

init()
