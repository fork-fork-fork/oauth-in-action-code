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
// 클라이언트는 자신이 대화하는 서버가 무엇이고, 어떻게 대화해야 하는지 알아야 함
// 서버의 인가 엔드포인트, 토큰 엔드포인트의 주소도 필요
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
// 신뢰할 수 있는 OAuth 클라이언트
var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1", // 인가 서버가 할당
	// 클라이언트가 인가 서버로부터 자기자신을 인증받기 위해 공유된 비밀번호를 가짐
	// client_secret은 다양한 방법으로 인가 서버의 토큰 엔드포인트에 전달 가능: 여기서는 http basic 이용
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

// 인가 프로세스: 사용자를 인가 엔드포인트 주소로 이동시킴
app.get('/authorize', function(req, res){

	access_token = null;

	state = randomstring.generate(); // 랜덤 값 할당

	var options = {
		response_type: 'code',
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	}
	console.log('options: ', options)
	// options:  {
	// 	response_type: 'code',
	// 	client_id: 'oauth-client-1',
	// 	redirect_uri: 'http://localhost:9000/callback',
	// 	state: '2zYIjKvGYA8wGgGJVMmCr1Nw7SgydbQ0'
	// }

	// authServer.authorizationEndpoint: http://localhost:9001/authorize
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, options);
	// 인가 프로세스를 시작하기 위해, 적당한 질의 파라미터를 url에 포함시킴 -> 사용자를 서버의 인가 엔드포인트로 리다이렉트

	console.log("redirect", authorizeUrl);
	// redirect http://localhost:9001/authorize?response_type=code&client_id=oauth-client-1&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&state=2zYIjKvGYA8wGgGJVMmCr1Nw7SgydbQ0

	res.redirect(authorizeUrl); // 사용자의 웹 브라우저를 인가 엔드포인트로 리다이렉트 시킴
});

// 클라이언트로의 리다이렉트는 이 함수에 의해 수행
// 이 때, 클라이언트로 전달되는 http 요청은 직접적인 요청에 대한 http 응답이 아니라, 인가 서버로부터 리다이렉트 된 것임
app.get('/callback', function(req, res){

	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		return;
	}

	if (req.query.state != state) {
		console.log('State DOES NOT MATCH: expected %s got %s', state, req.query.state);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code; // 클라이언트는 인가 서버가 전달한 인가 코드를 전달된 파라미터(code) 에서 읽음

	// 인가 코드를 추출해 토큰 엔드포인트로 직접 http post 전송
	// 인가 코드는 폼 파라미터로 전달됨
	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0] // 더 이상 리다리렉트 하지 않는데 이걸 포함해 토큰 엔드 포인트에 전달하는 이유?
		// -> OAuth 스펙에 의해, 인가 요청에 리다이렉트 uri가 포함돼 있었다면 토큰을 요청할 때도 그것과 동일한 uri를 함께 전달해야 함
		// -> 공격자가 침해된 리다이렉트 uri와 세션에 인가 코드를 삽입하는 것을 방지
	});

	// 클라이언트는 자신이 전달하는 요청이 http 폼 인코딩 됐다는 것을 나타내기 위한 헤더와 클라이언트 인증을 위한 http basic 인증 헤더를 함께 포함해 전달
	// http basic 인증을 위한 Authorization 헤더는 사용자 이름과 비밀번호를 : 문자로 연결해 base64fh dlszheldgks answkduf
	// OAuth 2.0에서는 클라이언트 id를 사용자 이름으로, 시크릿을 비밀번호로 사용하길 권장함 => 사용자 이름, 비번 모두 url 인코딩 됨
	var headers = { // http basic 인코딩을 위한 간단한 유틸리티 함수
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	// 서버의 인가 엔드포인트로 post 요청을 보냄
	var tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	});

	console.log('Requesting access token for code %s',code);
	// Requesting access token for code cVpgKsHP

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
		// 요청이 성공적으로 수행되면, 인가 서버는 액세스 토큰과 다른 몇 가지 값을 함께 포함하는 json 객체 반환

		access_token = body.access_token; // 추출한 액세스 토큰을 이후에도 사용할 수 있도록 저장
		console.log('Got access token: %s', access_token);
		// Got access token: epGKcWqGReYshTptfuhfre3lMFUnGadR

		res.render('index', {access_token: access_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});
// 액세스 토큰을 얻어 저장한 후: 웹 브라우저상에 사용자를 토큰 값을 표시하는 페이지로 이동
// 실제 OAuth 애플리케이션에서는 액세스 토큰 값을 표시해주지 않음
// 액세스 토큰은 클라이언트가 보호해야 하는 비밀 정보이기 때문

app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
		res.render('error', {error: 'Missing Access Token'});
		return;
	}

	console.log('Making request with access token %s', access_token);

	var headers = {
		'Authorization': 'Bearer ' + access_token
	};

	var resource = request('POST', protectedResource,
		{headers: headers}
	);

	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
		access_token = null;
		res.render('error', {error: resource.statusCode});
		return;
	}


});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);	// 자바스크립트의 url 라이브러리를 이용, 사용자를 리다이렉트할 목적지 url를 만듦
	delete newUrl.search;
	// 해당 url 에 전달할 질의 파라미터를 포맷에 맞게 만들고, url 인코딩 수행
	// 그런 다음, 작업을 위한 유틸리티 함수, 프런트 채널 통신을 위해 url을 올바로 만들고 질의 파라미터를 추가해야 함
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

