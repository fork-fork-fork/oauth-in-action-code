var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var base64url = require('base64url');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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
	"scope": "foo bar"
};

//var client = {};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

// 인가를 요청하는 코드 부분
app.get('/authorize', function(req, res){

	access_token = null;
	scope = null;

	// 클라이언트 자격 증명 플로에서는 리소스 소유자에게 리다렉트하지 않고 토큰 앤드 포인트 직접 호출
	// 인가 코드 그랜트 타입에서 콜백 uri를 처리하는 기반으로 작업
	// 즉, 클라이언트 자격 증명은 HTTP Basic 인증으로 포함시켜 HTTP POST를 전달
	var form_data = qs.stringify({
		grant_type: 'client_credentials',
		scope: client.scope
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	var tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	});

	// 전달된 응답 파싱
	// 단, 응답에 리프레시 토큰이 포함되지 않음(앞 예제와 차이점)
	// -> 클라이언트는 언제든지 사용자 개입 없이 새로운 토큰을 쉽게 요청할 수 있으므로, 리프레시 토큰 사용 필요 없음
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;

		scope = body.scope;

		res.render('index', {access_token: access_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}

	// 토큰을 전달받으면 클라이언트는 앞의 경우와 마찬가지로, 리소스 서버에 요청을 보낼 수 있음
	// 보호된 리소스는 액세스 토큰을 수신, 그것의 유효성을 검증하기 때문에 요청을 처리하는 코드를 특별히 변경하지 않아도 됨

});

app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}

	console.log('Making request with access token %s', access_token);

	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
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
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}

});

var encodeClientCredentials = function(clientId, clientSecret) {
	return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
	var host = server.address().address;
	var port = server.address().port;
	console.log('OAuth Client is listening at http://%s:%s', host, port);
});

