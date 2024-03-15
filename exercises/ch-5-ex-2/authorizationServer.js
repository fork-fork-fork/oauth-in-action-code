var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"]
	}
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){

	var client = getClient(req.query.client_id);

	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {

		var reqid = randomstring.generate(8);

		requests[reqid] = req.query;

		res.render('approve', {client: client, reqid: reqid });
		return;
	}

});

app.post('/approve', function(req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', {error: 'No matching authorization request'});
		return;
	}

	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access
			var code = randomstring.generate(8);

			// save the code and request for later
			codes[code] = { request: query };

			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else {
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
		// user denied access
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}

});

app.post("/token", function(req, res){

	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}

	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}

		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}

	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	if (req.body.grant_type == 'authorization_code') {

		var code = codes[req.body.code];

		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				// 리프레시 토큰 생성, nosql 데이터베이스에 저장
				var access_token = randomstring.generate();
				var refresh_token = randomstring.generate();

				nosql.insert({ access_token: access_token, client_id: clientId });
				nosql.insert({ refresh_token: refresh_token, client_id: clientId });
				// 인가 서버와 보호된 리소스가 각 토큰을 구별할 수 있도록, 리프레시 토큰을 저장할 때 사용하는 키를 다르게 함
				// 토큰 발급 이후 인가 서버에서는 리프레시 토큰만 사용함
				// 보호된 리소스에서는 엑세스 토큰만 사용되기 때문에 키를 다르게 해 저장하는 것이 중요

				console.log('Issuing access token %s', access_token);

				// 토큰을 모두 생성, 저장 후 클라이언트에게 두 토큰 전달
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token };
				// token_type 파라미터는 액세스 토큰에만 적용
				// 리프레시 토큰 또한 만료될 수 있지만, 생명주기가 상당히 기므로, 만료에 대한 정보를 따로 제공하지 않음
				// 리프레시 토큰이 더 이상 유효하지 않게 되면, 클라이언트는 처음에 액세스 토큰을 얻기 위해 사용한 인가 코드 그랜트와 같은 OAuth 인가 그랜트 플로를 다시 수행

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);

				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}


		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}

		// 리프레시 토큰 발급 후, 액세스 토큰 갱신 요청
		// OAuth 2.0 에서 리프레시 토큰은 토큰 엔드포인트에서 특별한 종류의 인가 그랜트로서 사용됨
	} else if (req.body.grant_type == 'refresh_token') {

		// 토큰 저장소에 전달된 리프레시 토큰이 있는지 확인
		nosql.one().make(function(builder) {
			builder.where('refresh_token', req.body.refresh_token);
			builder.callback(function(err, token) {
				if (token) { // 동일한 리프레시 토큰을 찾은 경우
					console.log("We found a matching refresh token: %s", req.body.refresh_token);

					// 해당 토큰이 토큰 엔드포인트에서 인가한 클라이언트에게 발급한 토큰인지 확인
					if (token.client_id != clientId) {

						// 확인 결과 침해됐다고 판단 시, 해당 리프레시 토큰을 저장소에서 삭제
						nosql.remove().make(function(builder) { builder.where('refresh_token', req.body.refresh_token); });
						res.status(400).json({error: 'invalid_grant'});
						return;
					}

					// 모든 확인 작업 통과 시
					// 리프레시 토큰을 기반, 새로운 액세스 토큰 생성 -> 저장 -> 클라이언트에게 전달
					// 이 때, 토큰 엔드포인트에서 전달되는 응답은 다른 OAuth 그랜트 타입의 경우와 동일
					// 클라이언트가 리프레시 토큰이나 인가 코드를 통해 발급받은 액세스 토큰에 대해 특별한 처리를 할 필요가 없다는 것을 의미
					// 또한, 액세스 토큰 갱신을 위해 사용된 동일한 리프레시 토큰을 다시 클라이언트에게 전달하기에, 클라이언트는 이후 액세스 토큰을 갱신하기 위해 해당 리프레시 토큰을 재사용 가능
					var access_token = randomstring.generate();
					nosql.insert({ access_token: access_token, client_id: clientId });
					var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: token.refresh_token };
					res.status(200).json(token_response);
					return;
				} else {
					console.log('No matching token was found.');
					res.status(400).json({error: 'invalid_grant'});
					return;
				};
			})
		});
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}

	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
	var host = server.address().address;
	var port = server.address().port;

	console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});

