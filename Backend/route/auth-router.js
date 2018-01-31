'use strict';

const {Router} = require('express');
const jsonParser = require('body-parser').json();
const Account = require('../model/account');
const httpErrors = require('http-errors');
const logger = require('../lib/logger');
const superagent = require('superagent');

const basicAuthMiddleware = require('../lib/basic-auth-middleware');
const GOOGLE_OAUTH_URL = 'https://www.googleapis.com/oauth2/v4/token';
const OPEN_ID_URL = 'https://www.googleapis.com/plus/v1/people/me/openIdConnect';

const authRouter = module.exports = new Router();

authRouter.get('/oauth/google', (request, response, next) => {
	if(!request.query.code) {
		response.redirect(process.env.CLIENT_URL);
	} else {
		logger.log('info', {code: request.query.code});
		return superagent.post(GOOGLE_OAUTH_URL)
			.type('form')
			.send({
				code: request.query.code,
				grant_type: 'authorization_code',
				client_id: process.env.GOOGLE_CLIENT_ID,
				client_secret: process.env.GOOGLE_CLIENT_SECRET,
				redirect_uri: `${process.env.API_URL}/oauth/google`,
			})
			.then(response => {
				logger.log('info','Back from GOOGLE_OAUTH_URL');
				if(!response.body.access_token)
					throw new Error('No access token');

				return response.body.access_token;
			})
			.then(accessToken => {
				logger.log('info', 'Getting OPEN_ID_URL');
				return superagent.get(OPEN_ID_URL)
				.set('Authorization', `Bearer ${accessToken}`);
			})
			.then(response => {
				logger.log('info', 'Back from OPEN_ID_URL');
				logger.log('info', {profile: response.body});

				return Account.handleGoogleAuth(response.body);
			})
			.then(account => account.createToken())
			.then(token => {
				response.cookie('X-Accontmon-OAuth-Token', '');
				response.redirect(process.env.CLIENT_URL + '?error=oauth');
			});
	}
});

authRouter.post('/signup', jsonParser, (request, response, next) => {
	if(!request.body.username || !request.body.email || !request.body.password)
		return next(httpErrors(400, '__ERROR__ Username, email, and password are required to create an account.'));

		Account.create(request.body.username, request.body.email, request.body.password)
			.then(user => user.createToken())
			.then(token => response.json({token})) 
			.catch(next);
});

authRouter.get('/login', basicAuthMiddleware, (request, response, next) => {
	if(!request.account) {
		return next(new httpErrors(404, '__ERROR__ not found'));
	}

	return request.account.createToken()
		.then(token => response.json({token}))
		.catch(next);
});