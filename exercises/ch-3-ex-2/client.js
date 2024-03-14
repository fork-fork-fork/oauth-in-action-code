var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');


var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "foo"
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = '987tghjkiu6trfghjuytrghj';
var scope = null;
var refresh_token = 'j2r3oj32r23rmasd98uhjrk2o3i';

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope, refresh_token: refresh_token});
});

app.get('/authorize', function(req, res){

	access_token = null;
	scope = null;
	state = randomstring.generate();

	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});

	console.log("redirect", authorizeUrl);
	res.redirect(authorizeUrl);
});

app.get('/callback', function(req, res){

	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		return;
	}

	var resState = req.query.state;
	if (resState != state) {
		console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + Buffer.from(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint,
		{
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token for code %s',code);

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}

		scope = body.scope;
		console.log('Got scope: %s', scope);

		res.render('index', {access_token: access_token, scope: scope, refresh_token: refresh_token});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

app.get('/fetch_resource', function(req, res) {

	console.log('Making request with access token %s', access_token);
	// Making request with access token 987tghjkiu6trfghjuytrghj
	// Making request with access token ZeKXR0tO3QwIg8LSGIdV7xoKJVCwlo6y

	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};

	var resource = request('POST', protectedResource,
		{headers: headers}
	);

	// 토큰 갱신 처리
	if (resource.statusCode >= 200 && resource.statusCode < 300) {	// 상태 코드 값 확인
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
		access_token = null; // 기존 액세스 토큰 무효화
		if (refresh_token) {
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: resource.statusCode});
			return;
		}
	}


});

var refreshAccessToken = function(req, res) {
	var form_data = qs.stringify({ // 토큰 엔드포인트에 보낼 요청을 만듦
		grant_type: 'refresh_token', // 액세스 토큰 갱신은 인가 그랜트의 특별한 경우므로, refresh_token 값 할당 및 파라미터에 포함
		refresh_token: refresh_token
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};
	console.log('Refreshing token %s', refresh_token);
	// Refreshing token j2r3oj32r23rmasd98uhjrk2o3i
	var tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	});
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		// Got access token: ZeKXR0tO3QwIg8LSGIdV7xoKJVCwlo6y

		if (body.refresh_token) {
			refresh_token = body.refresh_token; // 전달된 액세스 토큰 저장
			// 인가 서버가 전달한 데이터에는 앞서 전달한 것과는 다른 리프레시 토큰이 포함됨
			// 클라이언트는 새로운 리프레시 토큰을 받으면, 이전의 리프레시 토큰은 폐기하고 새로운 리프레시 토큰 사용함
			console.log('Got refresh token: %s', refresh_token);
			// Got refresh token: j2r3oj32r23rmasd98uhjrk2o3i
		}
		scope = body.scope;
		console.log('Got scope: %s', scope); // Got scope: undefined

		// try again
		// 최종적으로 클라이언트는 리소스를 다시 요청함
		// 리프레시 토큰 갱신은 원래 클라이언트가 /fetch_resource url 요청으로 보내짐으로써 이뤄진 것 -> 클라이언트는 다시 /fetch_resource url로 리다이렉트함
		res.redirect('/fetch_resource');
		return;
	} else { // 리프레시 토큰을 갱신하지 못한 경우
		console.log('No refresh token, asking the user to get a new access token');
		// tell the user to get a new access token
		refresh_token = null; // 기존의 액세스 토큰과 리프레시 토큰을 폐기, 에러 출력
		res.render('error', {error: 'Unable to refresh token.'});
		return;
	}
};

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

var encodeClientCredentials = function(clientId, clientSecret) {
	return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
	var host = server.address().address;
	var port = server.address().port;
	console.log('OAuth Client is listening at http://%s:%s', host, port);
});

