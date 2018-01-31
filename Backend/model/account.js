'use strict';

const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const httpErrors = require('http-errors');
const jsonWebToken = require('jsonwebtoken');	
const logger = require('../lib/logger');


const accountSchema = mongoose.Schema ({
	passwordHash: {
		type: String,
		required: true,
	},
	email: {
		type: String,
		required: true,
		unique: true,
	},
	username: {
		type: String,
		required: true,
		unique: true,
	},
	tokenSeed: {
		type: String,
		required: true,
		unique: true,
	},
	created: {
		type: Date,
		default: () => new Date(),
	},
	googleOAuth: {
		type: Boolean,
		default: false,
	}
});

accountSchema.methods.verifyPassword = function(password) {
	return bcrypt.compare(password, this.passwordHash)
		.then(response => {
			if (!response) 
				throw new httpErrors(401, '__AUTH__ Incorrect username or password.');
			return this;
		});
};

accountSchema.methods.createToken = function() {
	this.tokenSeed = crypto.randomBytes(64).toString('hex');

	return this.save()
		.then(account => {
			return jsonWebToken.sign({
				tokenSeed: account.tokenSeed}, process.env.SECRET);
		});
};

const Account = module.exports = mongoose.model('account', accountSchema);

Account.createFromSignup = function(user) {
	if(!user.password || !user.email || !user.username)
		throw new httpErrors(400, '__AUTH__ invalid user');

		let {password} = user;

		user = Object.assign({}, user, {password:undefined});

	const HASH_SALT_ROUNDS = 8;

	return bcrypt.hash(password, HASH_SALT_ROUNDS)

	.then(passwordHash => {
		let tokenSeed = crypto.randomBytes(64).toString('hex');
		let data = Object.assign({}, user, {passwordHash, tokenSeed});
		return new Account(data).save();
	});
};

Account.handleGoogleAuth = function(googlePlusProfile) {
	return Account.findOne({email: googlePlusProfile.email})
	.then(account => {
		if(account) {
			if(account.googleOAuth)
				return account;

			throw new Error('An account was found, but it has not been connected via Google');
		}

		logger.log('info', 'Ready to create account');

		return new Account({
			username: googlePlusProfile.email.split('@')[0],
			email: googlePlusProfile.email,
			passwordHash: crypto.randomBytes(32).toString('hex'),
			tokenSeed: crypto.randomBytes(32).toString('hex'),
			googleOAuth: true,
		}).save();
	});
};

