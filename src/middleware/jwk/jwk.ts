/**
 * @module
 * JWK Auth Middleware for Hono.
 */

import type { Context } from '../../context'
import { getCookie, getSignedCookie } from '../../helper/cookie'
import { HTTPException } from '../../http-exception'
import type { MiddlewareHandler } from '../../types'
import type { CookiePrefixOptions } from '../../utils/cookie'
import { Jwt } from '../../utils/jwt'
import '../../context'
import type { HonoJsonWebKey } from '../../utils/jwt/jws'

/**
 * JWK Auth Middleware for Hono.
 *
 * @see {@link https://hono.dev/docs/middleware/builtin/jwk}
 *
 * @param {object} options - The options for the JWK middleware.
 * @param {HonoJsonWebKey[] | ((ctx: Context) => Promise<HonoJsonWebKey[]> | HonoJsonWebKey[])} [options.keys] - The values of your public keys, or an async function that returns them.
 * @param {string | ((ctx: Context) => Promise<string> | string)} [options.jwks_uri] - If set, attempt to fetch JWKs from this URI, expecting a JSON response with `keys` which are added to the provided options.keys
 * @param {string} [options.cookie] - If set, the middleware retrieves the token from a cookie (optionally signed).
 * @param {RequestInit} [init] - Optional init options for the `fetch` request when retrieving JWKS from a URI.
 * @returns {MiddlewareHandler} The middleware handler function.
 *
 * @example
 * ```ts
 * const app = new Hono()
 *
 * app.use("/auth/*", jwk({ jwks_uri: (c) => `https://${c.env.backendServer}/.well-known/jwks.json` }))
 *
 * app.get('/auth/page', (c) => {
 *   return c.text('You are authorized')
 * })
 * ```
 */

export const jwk = (
  options: {
    keys?: HonoJsonWebKey[] | ((ctx: Context) => Promise<HonoJsonWebKey[]> | HonoJsonWebKey[])
    jwks_uri?: string | ((ctx: Context) => Promise<string> | string)
    cookie?:
      | string
      | { key: string; secret?: string | BufferSource; prefixOptions?: CookiePrefixOptions }
    skip_if_no_token?: boolean
  },
  init?: RequestInit
): MiddlewareHandler => {
  if (!options || !(options.keys || options.jwks_uri)) {
    throw new Error('JWK auth middleware requires options for either "keys" or "jwks_uri" or both')
  }

  if (!crypto.subtle || !crypto.subtle.importKey) {
    throw new Error('`crypto.subtle.importKey` is undefined. JWK auth middleware requires it.')
  }

  return async function jwk(ctx, next) {
    const credentials = ctx.req.raw.headers.get('Authorization')
    let token
    if (credentials) {
      const parts = credentials.split(/\s+/)
      if (parts.length !== 2) {
        const errDescription = 'invalid credentials structure'
        throw new HTTPException(401, {
          message: errDescription,
          res: unauthorizedResponse({
            ctx,
            error: 'invalid_request',
            errDescription,
          }),
        })
      } else {
        token = parts[1]
      }
    } else if (options.cookie) {
      if (typeof options.cookie == 'string') {
        token = getCookie(ctx, options.cookie)
      } else if (options.cookie.secret) {
        if (options.cookie.prefixOptions) {
          token = await getSignedCookie(
            ctx,
            options.cookie.secret,
            options.cookie.key,
            options.cookie.prefixOptions
          )
        } else {
          token = await getSignedCookie(ctx, options.cookie.secret, options.cookie.key)
        }
      } else {
        if (options.cookie.prefixOptions) {
          token = getCookie(ctx, options.cookie.key, options.cookie.prefixOptions)
        } else {
          token = getCookie(ctx, options.cookie.key)
        }
      }
    }

    if (!token) {
      if (options.skip_if_no_token) {
        return next()
      }
      const errDescription = 'no authorization included in request'
      throw new HTTPException(401, {
        message: errDescription,
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_request',
          errDescription,
        }),
      })
    }

    let payload
    let cause
    try {
      const keys = typeof options.keys === 'function' ? await options.keys(ctx) : options.keys
      const jwks_uri =
        typeof options.jwks_uri === 'function' ? await options.jwks_uri(ctx) : options.jwks_uri
      payload = await Jwt.verifyFromJwks(token, { keys, jwks_uri }, init)
    } catch (e) {
      cause = e
    }

    if (!payload) {
      if (cause instanceof Error && cause.constructor === Error) {
        throw cause
      }
      throw new HTTPException(401, {
        message: 'Unauthorized',
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_token',
          statusText: 'Unauthorized',
          errDescription: 'token verification failure',
        }),
        cause,
      })
    }

    ctx.set('jwtPayload', payload)

    await next()
  }
}

function unauthorizedResponse(opts: {
  ctx: Context
  error: string
  errDescription: string
  statusText?: string
}) {
  return new Response('Unauthorized', {
    status: 401,
    statusText: opts.statusText,
    headers: {
      'WWW-Authenticate': `Bearer realm="${opts.ctx.req.url}",error="${opts.error}",error_description="${opts.errDescription}"`,
    },
  })
}
