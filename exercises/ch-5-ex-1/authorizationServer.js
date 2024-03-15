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

// client information: 클라이언트 정보 저장
// 서버에 대한 모든 클라이언트 정보가 여기 저장됨
// 여러 개의 OAuth 클라이언트를 처리한다고 가정하므로, 배열 사용
var clients = [

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"]
	}
];

var codes = {};

var requests = {};

// 클라이언트 ID를 이용해 해당 클라이언트의 정보를 찾을 수 이도록 해야 함
// 보통 데이터베이스의 경우 질의를 하면 되나, 여기서는 간단한 함수를 만들어 동일한 클라이언트의 정보를 데이터 구조체 안에서 찾음
var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};
// 클라이언트 ID를 기준으로 클라이언트 정보 리스트를 차례대로 검색
// 원하는 클라이언트 정보를 찾으면 해당 객체를 반환, 찾지 못하면 undefined 반환

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){

	// 인가를 요청한 클라이언트 확인
	// 인가 서버는 해당 클라이언트가 등록된 것인지 확인
	var client = getClient(req.query.client_id);

	// 어느 클라이언트가 인가를 요청한 것인지 알게 됐으므로, 전달된 요청 자체에 대한 몇 가지 체크 수행
	// client_id 는 공개된 정보이므로, 전달된 요청이 적법한지 확인 = redirect_uri
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		// 등록된 클라이언트 정보의 redirect_uri 와 전달된 값이 같지 않다면 에러 발생
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {

		// 인가 서버는 전달되는 요청의 파라미터를 사용자가 승인한 이후 다시 참조할 수 있도록 request 변수에 저장(임의 값)
		var reqid = randomstring.generate(8);
		requests[reqid] = req.query;

		// 인가 서버는 approve.html 페이지로 클라이언트 정보와 앞서 요청 정보를 저장하는 데 사용한 임의의 키 값을 함께 전달
		res.render('approve', {client: client, reqid: reqid }); // 임의의 키 값 reqid는 폼의 숨긴 속성의 값으로 전달됨
		// 사용자가 클라이언트에게 권한을 위임할 것인지 여부를 판단할 수 있도록, 사용자에게 클라이언트에 대한 정보를 출력
		// 이 때 사용되는 임의의 키 값: 다음 단계 추가 처리를 위해 원래 전달된 요청 데이터를 찾는 데 사용됨 -> 간단한 CSRF 공격 차단 효과 제공
		return;
	}

});

// http 요청은 http 폼 인코딩된 형태의 값으로 전달됨
app.post('/approve', function(req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		// 지연된 인가 요청을 찾지 못한다면, 교차 사이트 위조 공격일 수 있으므로 -> 사용자에게 에러 페이지 보여 줌
		res.render('error', {error: 'No matching authorization request'});
		return;
	}

	if (req.body.approve) { // 사용자가 접근 권한을 인가했을 때
		if (query.response_type == 'code') { // 클라이언트가 어떤 종류의 응답을 요청한 것인지 확인(인가 코드 그랜트 타입 구현 처리에 대해, response_type = code 인지 확인)
			// user approved access

			// 어떤 종류의 응답을 해야 하는지 알게 됐으므로, 클라이언트에게 전달한 인가 코드를 생성
			// 생성한 코드는 서버 어딘가 저장해 놓음 -> 이후 클라이언트가 토큰 엔드포인트를 호출했을 때, 해당 클라이언트에게 전달할 인가 코드를 찾아볼 수 있기 때문
			// 여기서는 서버상의 객체에 저장하지만, 실제 서비스에서는 주로 데이터베이스에 저장됨
			// 어떤 경우든 인가 코드로 접근이 가능해야 함
			var code = randomstring.generate(8);

			// save the code and request for later
			codes[code] = { request: query };

			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			console.log('urlParsed: ', urlParsed);

			res.redirect(urlParsed);
			return;
		} else { // code 이외의 값이면 클라이언트에게 에러 반환
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else { // 사용자가 접근 권한을 거부했을 때
		// user denied access
		// 사용자가 접근 거부한 내용을 클라이언트에게 안전하게 전달해야 함
		// -> 프런트 채널 통신이므로 클라이언트에게 메시지를 직접 전달할 방법을 갖고 있지 않음
		// => 클라이언트가 요청을 전달하기 위해 사용한 방법과 동일한 방법 사용
		// 즉, 클라이언트의 리다이렉트 uri에 몇 가지 특별한 질의 파라미터를 추가, 사용자의 웹 브라우저를 그곳으로 리다이렉트 시킴
		// 클라이언트 리다이렉트 uri는 이런 목적으로 사용됨
		// 이 때문에, 클라이언트가 인가 서버에 요청을 보냈을 때 등록된 클라이언트 정보를 기준으로 클라이언트의 리다이렉트 uri를 검사한 것
		// => 클라이언트에 사용자가 접근 요청을 거부했다는 에러 메세지 전달
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}

});

// 토큰 엔드포인트 /token 에 대한 psot 요청을 처리하는 핸들러
app.post("/token", function(req, res){

	// 인가 서버는 OAuth 스펙에서 권장는 방법으로 클라이언트가 자격 증명 정보를 전달했는지 확인하기 위해 http의 Authorization 헤더 확인
	// -> 그 다음 폼 파라미터 확인
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		// 헤더를 읽어 각 변수에 저장
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}

	// otherwise, check the post body
	// 클라이언트가 전달한 클라이언트 id와 클라이언트 시크릿 값이 폼 파라미터로 전달됐는지 확인
	// Authorization 헤더 전달 외 2번째 방법으로 자격 증명 정보가 전달됐는지 확인
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}

		// 에러가 없을 시 입력된 폼 데이터에서 전달된 값 저장
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}

	// 헬퍼 함수 이용, 클라이언트가 등록된 클라이언트 리스트에 있는지 확인
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	// 클라이언트의 클라이언트 시크릿 값이 올바른지 확인
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	// grant_type 파라미터의 값 확인 -> 처리 가능한 그랜트 타입인지 확인
	// 여기서는 인가 코드 그랜트 타입만 지원하며, grant_type = authorization_code
	if (req.body.grant_type == 'authorization_code') { // 인가 코드 그랜트 처리

		var code = codes[req.body.code]; // 인가 코드 추출, 저장된 인가 코드 저장소에 해당 코드가 있는지 확인

		// 전달된 인가 코드를 코드 저장소에서 찾을 수 있다면, 클라이언트에게 발급된 것이라 판단
		// 인가 코드, 클라이언트 id, 인가 엔드포인트에 전달된 요청 내용이 함께 저장된 것을 확인할 수 있음
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			// 전달된 인가 코드가 유효하다는 것이 확인되면 무조건 서버 저장소에서 제거
			// 악의적인 클라이언트가 탈취된 인가 코드를 사용할 수 있기 때문, 한 번 사용된 인가 코드는 재사용 불가능

			if (code.request.client_id == clientId) { // 클라이언트 id 가 동일한지 비교

				// 클라이언트 id가 확인되면 액세스 토큰을 만들고 나중에 찾아볼 수 있도록 그것을 저장
				var access_token = randomstring.generate();
				nosql.insert({ access_token: access_token, client_id: clientId });
				// 엑세스 토큰을 nosql 데이터베이스 저장
				// 실제 OAuth 시스템에서는 액세스 토큰을 다양한 방법으로 저장하고 관리함

				console.log('Issuing access token %s', access_token);

				// 생성되고 저장된 토큰을 클라이언트에게 전달
				// 토큰 엔드포인트에서 클라이언트에게 전달하는 응답은 json 객체로, 액세스 토큰과 토큰 타입이 포함됨
				// 여기서는 Bearer 토큰 사용
				var token_response = { access_token: access_token, token_type: 'Bearer' }; // token_type: 클라이언트가 자신에게 전달된 토큰이 어떤 종류고, 보호된 리소스에 접근하기 위해 어떻게 사용해야 하는지 알 수 있도록 하는 정보

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
	} else { // 지원하지 않는 그랜트 타입일 시 에러 반환
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

