/**
 * @module
 * JWT Auth Middleware for Hono.
 */
import type { MiddlewareHandler } from '../../types';
import type { CookiePrefixOptions } from '../../utils/cookie';
import '../../context';
import type { SignatureAlgorithm } from '../../utils/jwt/jwa';
import type { SignatureKey } from '../../utils/jwt/jws';
export type JwtVariables<T = any> = {
    jwtPayload: T;
};
/**
 * JWT Auth Middleware for Hono.
 *
 * @see {@link https://hono.dev/docs/middleware/builtin/jwt}
 *
 * @param {object} options - The options for the JWT middleware.
 * @param {SignatureKey} [options.secret] - A value of your secret key.
 * @param {string} [options.cookie] - If this value is set, then the value is retrieved from the cookie header using that value as a key, which is then validated as a token.
 * @param {SignatureAlgorithm} [options.alg=HS256] - An algorithm type that is used for verifying. Available types are `HS256` | `HS384` | `HS512` | `RS256` | `RS384` | `RS512` | `PS256` | `PS384` | `PS512` | `ES256` | `ES384` | `ES512` | `EdDSA`.
 * @returns {MiddlewareHandler} The middleware handler function.
 *
 * @example
 * ```ts
 * const app = new Hono()
 *
 * app.use(
 *   '/auth/*',
 *   jwt({
 *     secret: 'it-is-very-secret',
 *   })
 * )
 *
 * app.get('/auth/page', (c) => {
 *   return c.text('You are authorized')
 * })
 * ```
 */
export declare const jwt: (options: {
    secret: SignatureKey;
    cookie?: string | {
        key: string;
        secret?: string | BufferSource;
        prefixOptions?: CookiePrefixOptions;
    };
    alg?: SignatureAlgorithm;
}) => MiddlewareHandler;
export declare const verify: (token: string, publicKey: SignatureKey, alg?: SignatureAlgorithm) => Promise<import("../../utils/jwt/types").JWTPayload>;
export declare const decode: (token: string) => {
    header: import("../../utils/jwt/jwt").TokenHeader;
    payload: import("../../utils/jwt/types").JWTPayload;
};
export declare const sign: (payload: import("../../utils/jwt/types").JWTPayload, privateKey: SignatureKey, alg?: SignatureAlgorithm) => Promise<string>;
